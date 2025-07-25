** All of the below has been implemented**

Implement behavioral profiling to blacklisted ip addresses and store this "profile"
into a globally accessible data which can be queried to create a global blaclist state

Implement endpoint traffic analysis as well, what would need to be done is, that root handler "/" would have to be 
modified in someway, so that all the calls are being mapped in a hashmap perhaps ?? then once the set values cross "rate_limit", blacklist is updated -> behavioral profiling begins (enqueue onto a profiling agent)

on doing so the analysis part won't be limited to only rate limit, I'm foreseeing the intelligent agent to be capable of adapting like mahoraga "cringe ik" but it would help if the filtering got stricter for those profile that were matched

for that a separate indentity analyser would need to be developed that checcks for the similarity and enforces the weight for screening strictness for the ip addresses that are being checked.

next important part is the traffic anaysis part, I don't know how to currently implement the trafic analysis since all the attacks can be highly differentiated, do we need to check for graph algorithms like bursts or spikes ? who knows

to end it i also need to make all the reverse proxies a p2p archtecture , sort of like a mesh of hyper intelligent DDOS mitigators that are constantly sharing knowledge thru the use of off-prem dbs that have longterm as well as caching mecchanisms