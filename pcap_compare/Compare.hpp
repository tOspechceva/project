#pragma once
#include "ParallelPcapReader.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <numeric>
#include <tuple>

namespace experiment {
using namespace traffic;
using Clock = std::chrono::steady_clock;

// Снимок входа общий для всех методов. Храним сырые байты и смещения,
// чтобы не создавать отдельное выделение памяти на каждый пакет.
struct Sample {
    std::vector<Record> records;
    std::vector<unsigned char> bytes;
    const unsigned char* data(std::size_t i) const {
        return records[i].header.caplen ? bytes.data()+records[i].offset : nullptr;
    }
};

inline Sample load(const char* path, std::size_t limit) {
    char error[PCAP_ERRBUF_SIZE]{};
    std::unique_ptr<pcap_t,void(*)(pcap_t*)> input(pcap_open_offline(path,error),pcap_close);
    if (!input) throw std::runtime_error(error);
    if (pcap_datalink(input.get()) != DLT_EN10MB) throw std::runtime_error("Expected Ethernet");
    Sample s;
    pcap_pkthdr* h;
    const unsigned char* data;
    while (!limit || s.records.size() < limit) {
        int status = pcap_next_ex(input.get(), &h, &data);
        if (status == PCAP_ERROR_BREAK) break;
        if (status != 1) throw std::runtime_error(pcap_geterr(input.get()));
        s.records.push_back({*h,s.bytes.size()});
        if (h->caplen) s.bytes.insert(s.bytes.end(),data,data+h->caplen);
    }
    if (s.records.empty()) throw std::runtime_error("Empty sample");
    return s;
}

// Один и тот же фильтр во всех режимах. Поддерживает синтаксис libpcap.
class Filter {
    bpf_program program{};
public:
    explicit Filter(const char* expression) {
        std::unique_ptr<pcap_t,void(*)(pcap_t*)> p(pcap_open_dead(DLT_EN10MB,65535),pcap_close);
        if (!p || pcap_compile(p.get(),&program,expression,1,PCAP_NETMASK_UNKNOWN)<0)
            throw std::runtime_error(p ? pcap_geterr(p.get()) : "Cannot initialize filter");
    }
    ~Filter(){pcap_freecode(&program);}
    Filter(const Filter&)=delete;
    bool accepts(const Sample& s,std::size_t i) const {
        return pcap_offline_filter(&program,&s.records[i].header,s.data(i)) != 0;
    }
};

struct Item { std::size_t index; Packet packet; };
using Edge = std::tuple<Kind,std::string,std::string>;
struct Stats {
    Count seen=0, accepted=0;
    // Для каждого направления: число пакетов и сумма исходных длин.
    std::map<Edge,std::pair<Count,Count>> edges;
    void add(const Item& item,const Sample& s) {
        ++accepted;
        const Packet& p=item.packet;
        if (p.source.empty()) return;
        const Kind kind=p.kind==Kind::RawIPv4 ? Kind::IPv4 : p.kind;
        auto& weight=edges[{kind,p.source,p.destination}];
        ++weight.first;
        weight.second+=s.records[item.index].header.len;
    }
    void merge(const Stats& other) {
        seen+=other.seen; accepted+=other.accepted;
        for (const auto& [key,value]:other.edges) {
            auto& dest=edges[key];
            dest.first+=value.first; dest.second+=value.second;
        }
    }
};

inline Item decode(const Sample& s,std::size_t i) {
    const auto& h=s.records[i].header;
    return {i,parse(s.data(i),h.caplen,h.len)};
}

// Три стадии для целого набора: разбор, фильтрация, статистика.
inline void batch(const Sample& s,const Filter& f,std::size_t begin,std::size_t end,
                  std::vector<Item>& items,Stats& stats) {
    items.clear();
    for (auto i=begin;i<end;++i) items.push_back(decode(s,i));
    stats.seen+=end-begin;
    items.erase(std::remove_if(items.begin(),items.end(),[&](const Item& item){
        return !f.accepts(s,item.index);
    }),items.end());
    for (const auto& item:items) stats.add(item,s);
}

template<class T> class Queue {
    std::deque<T> values;
    const std::size_t capacity;
    std::mutex mutex;
    std::condition_variable readable,writable;
    bool closed=false;
public:
    explicit Queue(std::size_t cap):capacity(cap){}
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex);
        writable.wait(lock,[&]{return closed || values.size()<capacity;});
        if (closed) return false;
        values.push_back(std::move(item));
        readable.notify_one();
        return true;
    }
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        readable.wait(lock,[&]{return closed || !values.empty();});
        if (values.empty()) return false;
        item=std::move(values.front()); values.pop_front();
        writable.notify_one();
        return true;
    }
    void close() {
        std::lock_guard<std::mutex> lock(mutex);
        closed=true; readable.notify_all(); writable.notify_all();
    }
};

inline Stats pipeline(const Sample& s,const Filter& f,unsigned capacity) {
    Queue<Item> parsed(capacity), selected(capacity);
    Stats stats;
    // При исключении пробуждаем обе очереди, чтобы потоки могли завершиться.
    auto stop=[&]{parsed.close(); selected.close();};
    auto launch=[&](auto stage){
        return std::async(std::launch::async,[&,stage]{
            try {stage();} catch (...) {stop(); throw;}
        });
    };
    std::future<void> first,second;
    try {
        first=launch([&]{
            for(std::size_t i=0;i<s.records.size();++i)
                if(!parsed.push(decode(s,i))) break;
            parsed.close();
        });
        second=launch([&]{
            Item item{};
            while(parsed.pop(item))
                if(f.accepts(s,item.index) && !selected.push(std::move(item))) break;
            selected.close();
        });
        // Третий этап выполняется вызывающим потоком.
        Item item{};
        while(selected.pop(item)) stats.add(item,s);
        first.get(); second.get();
    } catch (...) {stop(); throw;}
    stats.seen=s.records.size();
    return stats;
}

inline Stats pool(const Sample& s,const Filter& f,unsigned workers) {
    constexpr std::size_t B=256;
    Queue<std::size_t> jobs(2ULL*workers);
    std::vector<std::future<Stats>> futures;
    Stats result;
    try {
        for(unsigned w=0;w<workers;++w)
            futures.push_back(std::async(std::launch::async,[&]{
                try {
                    Stats local; std::vector<Item> items; items.reserve(B);
                    std::size_t start;
                    while(jobs.pop(start))
                        batch(s,f,start,std::min(start+B,s.records.size()),items,local);
                    return local;
                } catch (...) {jobs.close(); throw;}
            }));
        for(std::size_t i=0;i<s.records.size();i+=B)
            if(!jobs.push(i)) break;
        jobs.close();
        for(auto& worker:futures) result.merge(worker.get());
    } catch (...) {jobs.close(); throw;}
    return result;
}

enum class Mode { Single, Batch, Pipeline, Pool };
struct Config {
    Mode mode;
    unsigned arg;
    std::string label;
    std::vector<double> seconds;
};

inline Stats process(const Config& c,const Sample& s,const Filter& f) {
    if(c.mode==Mode::Pipeline) return pipeline(s,f,c.arg);
    if(c.mode==Mode::Pool) return pool(s,f,c.arg);
    Stats stats;
    if(c.mode==Mode::Single) {
        for(std::size_t i=0;i<s.records.size();++i) {
            auto item=decode(s,i); ++stats.seen;
            if(f.accepts(s,i)) stats.add(item,s);
        }
    } else {
        std::vector<Item> items; items.reserve(c.arg);
        for(std::size_t i=0;i<s.records.size();i+=c.arg)
            batch(s,f,i,std::min(i+c.arg,s.records.size()),items,stats);
    }
    return stats;
}

inline void compare(const char* path,unsigned workers,unsigned repeats,std::size_t limit,const char* expression) {
    const auto start=Clock::now();
    const Sample s=load(path,limit);
    const double loadTime=std::chrono::duration<double>(Clock::now()-start).count();
    Filter f(expression);
    std::vector<Config> configs{{Mode::Single,1,"single (1 поток)",{}}};
    for(unsigned b:{1,16,64,256,1024})
        configs.push_back({Mode::Batch,b,"batch B="+std::to_string(b)+" (1 поток)",{}});
    for(unsigned q:{1,16,256})
        configs.push_back({Mode::Pipeline,q,"pipeline Q="+std::to_string(q)+" (3 этапа)",{}});
    for(std::size_t w=1;w<=workers;++w)
        configs.push_back({Mode::Pool,static_cast<unsigned>(w),"pool B=256 workers="+std::to_string(w),{}});
    Stats reference;
    std::cout<<std::fixed<<std::setprecision(4)<<"Записей: "<<s.records.size()
             <<" | чтение и подготовка: "<<loadTime<<" с | фильтр: "<<expression<<std::endl;
    for(std::size_t round=0;round<=repeats;++round) {
        for(std::size_t k=0;k<configs.size();++k) {
            auto& c=configs[(k+round)%configs.size()];
            std::cout<<(round ? "Измерение " : "Прогрев ")<<round<<" | "<<c.label<<std::flush;
            const auto t=Clock::now();
            Stats actual=process(c,s,f);
            const double elapsed=std::chrono::duration<double>(Clock::now()-t).count();
            if(!round && !k) reference=std::move(actual);
            else if(actual.seen!=reference.seen || actual.accepted!=reference.accepted || actual.edges!=reference.edges)
                throw std::runtime_error("Результаты режимов различаются: "+c.label);
            if(round) c.seconds.push_back(elapsed);
            std::cout<<" | "<<elapsed<<" с\n";
        }
    }
    std::cout<<"\nКонтроль: вход "<<reference.seen<<", прошло фильтр "<<reference.accepted
             <<", направленных связей с учётом типа "<<reference.edges.size()
             <<"\nРежим | медиана, с | мин, с | макс, с | пак/с | мкс/пак | ускорение\n";
    std::string winner,peakMode,bestPool;
    double baseline=0,best=1e300,peak=0,poolBest=1e300;
    for(auto& c:configs) {
        auto& v=c.seconds; std::sort(v.begin(),v.end());
        const double med=(v[(v.size()-1)/2]+v[v.size()/2])/2;
        if(c.mode==Mode::Single) baseline=med;
        if(med<best){best=med; winner=c.label;}
        if(c.mode==Mode::Pool && med<poolBest){poolBest=med; bestPool=c.label;}
        const double rate=s.records.size()/v.front();
        if(rate>peak){peak=rate;peakMode=c.label;}
        std::cout<<c.label<<" | "<<med<<" | "<<v.front()<<" | "<<v.back()<<" | "
                 <<s.records.size()/med<<" | "<<med*1e6/s.records.size()<<" | "<<baseline/med<<"x\n";
    }
    std::cout<<"Лучший режим по медиане: "<<winner<<", ускорение к single "<<baseline/best
             <<"x\nЛучший вариант пула: "<<bestPool<<", "<<poolBest<<" с"
             <<"\nМаксимальная скорость одного прогона: "<<peak<<" пак/с ("<<peakMode<<")\n";
}
}
