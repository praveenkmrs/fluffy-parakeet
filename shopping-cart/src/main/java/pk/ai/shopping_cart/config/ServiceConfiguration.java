package pk.ai.shopping_cart.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import pk.ai.shopping_cart.service.factory.ServiceFactory;

/**
 * Service configuration for managing service abstraction layer
 */
@Slf4j
@Configuration
public class ServiceConfiguration {

    private final Environment environment;
    private final ServiceFactory serviceFactory;

    public ServiceConfiguration(Environment environment, ServiceFactory serviceFactory) {
        this.environment = environment;
        this.serviceFactory = serviceFactory;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        String[] activeProfiles = environment.getActiveProfiles();
        log.info("Application started with profiles: {}", String.join(", ", activeProfiles));
        log.info("Service configuration: {}", serviceFactory.getServiceConfiguration());

        if (serviceFactory.isUsingStubServices()) {
            log.warn("=================================================================");
            log.warn("WARNING: Application is running with STUB services!");
            log.warn("This is intended for development and testing only.");
            log.warn("Payment and notification operations will be simulated.");
            log.warn("=================================================================");
        } else {
            log.info("Application is running with external service integrations.");
        }
    }
}
