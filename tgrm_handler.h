
#pragma once

#include <cstdio>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

typedef void (*tgrm_handler)(void*, size_t, void*);

inline std::map<uint16_t, std::vector<std::function<void(void*, size_t)>>> tgrm_func_handlers{};

template<typename FUNC, typename TC>
void tgrm_handler_reg(uint16_t type, FUNC&& func, TC* data) {

	tgrm_func_handlers[type].push_back([data, func = std::move(func)](void* frame, size_t sz)
		{
			func(frame, sz, data);
		});
}

inline void tgrm_handler_execute(uint16_t type, void* buf, size_t sz){
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
