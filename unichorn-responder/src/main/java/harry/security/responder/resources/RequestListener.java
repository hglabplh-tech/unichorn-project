package harry.security.responder.resources;

import iaik.cms.SecurityProvider;
import iaik.cms.ecc.ECCelerateProvider;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIKMD;
import org.harry.security.util.keystores.UnicProvider;
import org.pmw.tinylog.Logger;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;
import java.security.Security;

@WebListener
public class RequestListener implements ServletRequestListener {

    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {

    }

    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        Logger.trace("register IAIK providers");
        IAIKMD.addAsProvider();
        ECCelerate.insertProviderAt(3);
        Security.insertProviderAt(UnicProvider.getInstance(), 4);
        SecurityProvider.setSecurityProvider(new ECCelerateProvider());
        Logger.trace("register IAIK providers success");
    }

}
