global addrToagent : table[addr] of set[string] = table();

event http_header (c: connection, is_orig: bool, name: string, value: string){
	if(c$http?$user_agent){
		local src_ip=c$id$orig_h;
		local user_agent=to_lower(c$http$user_agent);
		if(src_ip in addrToagent){
			add (addrToagent[src_ip])[user_agent];
		}else{
			addrToagent[src_ip]=set(user_agent);
		}
	}
}

event zeek_done() {
	for (addr_ip in addrToagent) {
	    if (|addrToagent[addr_ip]| >= 3) {
	        print fmt("%s is a proxy", addr_ip);
	    }
	}
}
