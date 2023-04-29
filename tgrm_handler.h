
#pragma once

#include <cstdio>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include "knx_ip_tun.h"

typedef void (*tgrm_handler)(const char *, size_t, void*);

inline std::map<KNX_ST, std::vector<std::function<void(const char*, size_t)>>> tgrm_func_handlers{};

template<typename FUNC, typename TC>
void tgrm_handler_reg(KNX_ST type, FUNC&& func, TC* data) {

	tgrm_func_handlers[type].push_back([data, func = std::move(func)](const char* frame, size_t sz)
		{
			func(frame, sz, data);
		});
}

inline void tgrm_handler_execute(KNX_ST type, const char* buf, size_t sz){
	auto handler_element = tgrm_func_handlers.find(type);
	if (handler_element == tgrm_func_handlers.end())
	{
        printf("no handler for svc type %04x\n", type);
		return;
    }
    for (auto& f : handler_element->second) {
        f(buf, sz);
    }
}

inline void tgrm_handler_allfree(){
	tgrm_func_handlers.clear();
}
