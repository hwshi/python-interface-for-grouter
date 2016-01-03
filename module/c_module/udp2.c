#include "udp2.h"

module_config_t *udp2Config()
{
    printf("creating config..\n");
    module_config_t *config = (module_config_t*)malloc(sizeof(module_config_t));
    
    strcpy(config->name, "udp2");
    config->protocol = 17;
    config->processor = &udp2Protocol_Processor;
    config->command = &udp2Command_Line;
    strcpy(config->command_str, "udp2");
    printConfigInfo(config);
    return config;
}

int udp2Protocol_Processor()
{
    printf("[udp2Process] start!\n");
    return EXIT_SUCCESS;
}

void udp2Command_Line()
{
    printf("[udp2Command_Line] start!\n");
}
