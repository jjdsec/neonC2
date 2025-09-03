#ifndef AGENT_NETWORKLIB
#define AGENT_NETWORKLIB

// function signatures

typedef void (*net_client_handler_t)(int);

bool test_net_feature();
bool net_init(net_client_handler_t callback);

#endif // AGENT_NETWORKLIB