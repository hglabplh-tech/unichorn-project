package harry.security.responder.resources;

import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import org.pmw.tinylog.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.security.Security;

@WebListener
public class SecurityProviderInitializer implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent event) {
        Logger.trace("register IAIK providers");
        IAIKMD.addAsProvider();
        ECCelerate.insertProviderAt(3);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());
        Logger.trace("register IAIK providers success");
        //
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {}
}
