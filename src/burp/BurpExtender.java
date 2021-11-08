package burp;

import java.io.IOException;
import java.io.PrintWriter;
import org.eclipse.jetty.server.*;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.google.gson.*;

import org.eclipse.jetty.server.handler.AbstractHandler;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;

    public static void main(String[] args) {
        // spin up the server
        BurpExtender test = new BurpExtender();
        test.runServer();
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("PAC Server");
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.callbacks = callbacks;
		
        stdout.println("PAC Server extension initialized.");

		// unload resources when this extension is removed;
		callbacks.registerExtensionStateListener(this);
        
        this.runServer();
    }

    private static Server server;

    public void runServer() {
        server = new Server(37314);
        try {
            server.setHandler(new PACServerHandler(this));
            server.start();
            stdout.println("PAC server is now listening on localhost:37314");
            server.join();
        } catch (Exception e) {
            e.printStackTrace();
            stdout.println("An error occurred - maybe there is already a service running on port 37314?");
        }
        
    }

    private static String PAC_SCRIPT = "function FindProxyForURL(url, host) {\nvar i = 'PROXY %BURP%; DIRECT', o = [''%SIMPLESCOPE%], t = %ADVANCEDSCOPE%;\n    // since browsers do no longer allow PAC script to\n    // inspect the path and query strings of HTTPS URLs,\n    // this script does all its routing based on hostname alone\n	for (s in o)\n        // for simple scope, which works with prefixes\n        // we need to strip of anything following the third /\n        // and compare to the hostname\n        if(o[s].startsWith('https:')) {\n            if (o[s].length > 0 && url.indexOf(o[s].substring(0, o[s].indexOf('/', 8))) == 0)\n			    return i;\n        } else {\n            // if http we can compare full url still:\n            if (o[s].length > 0 && url.indexOf(o[s]) == 0)\n			    return i;\n        }\n		\n	for (s in t) \n		if (t[s].enabled && new RegExp(t[s].host).test(host))\n			return i;\n	return 'DIRECT';\n}";

    public class PACServerHandler extends AbstractHandler
    {
        BurpExtender burp;

        public PACServerHandler(BurpExtender burp) {
            this.burp = burp;
        }

        public void handle(String target, Request baseRequest,HttpServletRequest request,HttpServletResponse response) throws IOException, ServletException
        {
            if(!target.equals("/proxy.pac")) return;

            response.setContentType("text/html;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_OK);

            JsonArray proxy_listeners = new Gson().fromJson(burp.callbacks.saveConfigAsJson("proxy.request_listeners"), JsonObject.class)
                .get("proxy").getAsJsonObject().get("request_listeners").getAsJsonArray();
            JsonObject proxyConfig = null;
            
            // loop through proxy listeners to find a running one:
            for(int i=0; i < proxy_listeners.size(); i++) {
                if ( proxy_listeners.get(i).getAsJsonObject().get("running").getAsBoolean() ) {
                    proxyConfig = proxy_listeners.get(i).getAsJsonObject();
                }
            }
            
            if (proxyConfig == null) {
                baseRequest.setHandled(true);
                response.getWriter().println("Error: no running Burp proxy listeners found.");
                return;
            }

            String listen_mode = proxyConfig.get("listen_mode").getAsString();
            String burp_host =  null;
            String burp_port = proxyConfig.get("listener_port").getAsString();

            

            // load current burp configuration to find what ports Burp is listening on
            switch(listen_mode) {
                case "loopback_only":
                case "all_interfaces":
                    burp_host = "localhost";
                    break;
                case "specific_address":
                    burp_host = proxyConfig.get("listen_specific_address").getAsString();
                    break;
                
            }
            // generate a PAC script based on the Burp scope
            JsonObject scope = new Gson().fromJson(burp.callbacks.saveConfigAsJson("target.scope"), JsonObject.class);

            String scope_advanced = "[]";
            String scope_simple = "";

            if (scope.get("target").getAsJsonObject().get("scope").getAsJsonObject().get("advanced_mode").getAsBoolean()) {
                // if advanced scope
                scope_advanced = scope.get("target").getAsJsonObject().get("scope").getAsJsonObject().get("include").toString();
            } else {
                JsonArray scopeElements = scope.get("target").getAsJsonObject().get("scope").getAsJsonObject().get("include").getAsJsonArray();

                // print an array of scope elements
                
                for(int i=0; i < scopeElements.size(); i++) {
                    if ( scopeElements.get(i).getAsJsonObject().get("enabled").getAsBoolean()) {
                        // print the enabled scope
                        scope_simple += ",'"+scopeElements.get(i).getAsJsonObject().get("prefix").getAsString()+"'";
                    }
                }
            }

            baseRequest.setHandled(true);
            response.getWriter().print(PAC_SCRIPT
                .replace("%BURP%",burp_host+":"+burp_port)
                .replace("%SIMPLESCOPE%", scope_simple)
                .replace("%ADVANCEDSCOPE%", scope_advanced));
        }

    }

    @Override
    public void extensionUnloaded() {
        if(server != null) {
            try {
                server.stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
}
