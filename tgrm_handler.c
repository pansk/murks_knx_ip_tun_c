typedef void (* tgrm_handler)(void*, size_t, void*);

struct tgrm_func_handlers {
	uint16_t type;
	struct tgrm_func_list *l;
	struct tgrm_func_handlers *next;
} *tgrm_func_handlers = NULL;

struct tgrm_func_list {
	struct tgrm_func_list *next;
	tgrm_handler tgrm_handler;
	void* data;
};

void tgrm_handler_reg(uint16_t type, tgrm_handler func, void* data){
	struct tgrm_func_handlers* fhi;

	void add(struct tgrm_func_handlers* h){
		struct tgrm_func_list* fli = h->l;

		fli = malloc(sizeof(struct tgrm_func_list));
		fli->tgrm_handler = func; fli->data = data;
		fli->next = h->l; // next is current head
		h->l = fli; // new head
	}

	// find matching handler type
	for(fhi=tgrm_func_handlers; fhi != NULL; fhi = fhi->next){
		if(fhi->type == type) { // match!
			add(fhi);
			return;
		}
	}
	// type not in list: allocate and prepend type to list
	fhi = malloc(sizeof(struct tgrm_func_handlers));
	fhi->type = type;
	fhi->l = NULL; // empty list
	fhi->next = tgrm_func_handlers; // next is current head
	tgrm_func_handlers = fhi; // new head
	add(fhi);
}

void tgrm_handler_execute(uint16_t type, void* buf, size_t sz){
	struct tgrm_func_handlers *h;
	struct tgrm_func_list *l;
	for(h = tgrm_func_handlers; h != NULL; h = h->next){
		if(h->type == type){
			for(l = h->l; l != NULL; l = l->next)
				l->tgrm_handler(buf, sz, l->data); // execute handler
			return;
		}
	}
	printf("no handler for svc type %04x\n", type);
}

void tgrm_handler_allfree(){
	struct tgrm_func_handlers *h=tgrm_func_handlers, *nh;
	struct tgrm_func_list *l, *nl;
	for(; h!=NULL; h=nh){
		for(l = h->l; l != NULL; l = nl){
			nl = l->next;
			free(l);
		}
		nh = h->next;
		free(h);
	}
	tgrm_func_handlers=NULL;
};
