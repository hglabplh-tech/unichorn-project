package harry.security.responder.resources;

import org.pmw.tinylog.Configurator;
import org.pmw.tinylog.Level;
import org.pmw.tinylog.writers.FileWriter;

import java.util.Locale;

public class LoggerConfigSetter {
    public static boolean loConfigSet = false;

    public static void setLoggerConfig () {
        if (!loConfigSet) {
            Configurator.defaultConfig()
                    .writer(new FileWriter("unichorn.log"))
                    .locale(Locale.GERMANY)
                    .level(Level.TRACE)
                    .activate();
        }
        loConfigSet = true;
    }

}
