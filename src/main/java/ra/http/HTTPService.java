package ra.http;

import okhttp3.*;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.session.FileSessionDataStore;
import org.eclipse.jetty.server.session.NullSessionCache;
import org.eclipse.jetty.server.session.SessionCache;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.websocket.api.WebSocketPolicy;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest;
import org.eclipse.jetty.websocket.servlet.ServletUpgradeResponse;
import org.eclipse.jetty.websocket.servlet.WebSocketCreator;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;
import ra.common.Envelope;
import ra.common.file.Multipart;
import ra.common.messaging.DocumentMessage;
import ra.common.messaging.Message;
import ra.common.messaging.MessageProducer;
import ra.common.network.*;
import ra.common.route.ExternalRoute;
import ra.common.route.Route;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;
import ra.common.BrowserUtil;
import ra.common.Config;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

/**
 * HTTP Client as a service.
 */
public class HTTPService extends NetworkService {

    private static final Logger LOG = Logger.getLogger(HTTPService.class.getName());

    public static final String OPERATION_SEND = "SEND";
    public static final String OPERATION_REPLY = "REPLY";

    public static final String RA_HTTP_CLIENT_CONFIG = "ra-http.config";
    public static final String RA_HTTP_CLIENT_DIR = "ra.http.client.dir";
    public static final String RA_HTTP_CLIENT_TRUST_ALL = "ra.http.client.trustallcerts";

    public static int SESSION_INACTIVITY_INTERVAL = 60 * 60; // 60 minutes

    /**
     * Configuration of Servers in the form:
     *      API: name, API, address, port, concrete implementation ra.http.server.EnvelopeHandler
     *      PROXY: name, PROXY, address, port, concrete implementation ra.http.server.EnvelopeHandler
     *      Web App: name, WEB, address, port, concrete implementation ra.http.server.EnvelopeHandler, launch on start, relative resource directory, use WebSocket, websocket adaptor (optional)
     *      SPA Web App: name, SPA, address, port, concrete implementation ra.http.server.EnvelopeHandler, launch on start, relative resource directory, use WebSocket, websocket adaptor (optional)
     */
    public static final String RA_HTTP_SERVER_CONFIGS = "ra.http.server.configs";
    public static final String RA_HTTP_SERVER_DIR = "ra.http.server.dir";
    public static final String HANDLER_ID = "ra.http.server.handler.id";
    public static final String SESSION_ID = "ra.http.server.session.id";

    private boolean isTest = false;

    private Map<String, Server> servers = new HashMap<>();
    private Map<String, HandlerCollection> handlers = new HashMap<>();

    protected static final Set<String> trustedHosts = new HashSet<>();

    protected static final HostnameVerifier trustAllHostnameVerifier = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    protected static final HostnameVerifier hostnameVerifier = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return trustedHosts.contains(hostname);
        }
    };

    protected X509TrustManager trustAllX509TrustManager = new X509TrustManager() {

        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
    };

    // Create a trust manager that does not validate certificate chains
    protected TrustManager[] trustAllTrustManager = new TrustManager[]{trustAllX509TrustManager};

    protected ConnectionSpec httpSpec;
    protected OkHttpClient httpClient;

    protected ConnectionSpec httpsStrongSpec;
    protected volatile OkHttpClient httpsStrongClient;
    private boolean trustAllCerts;
    private SSLContext trustAllSSLContext;

    protected Properties config;

    protected Proxy proxy = null;

    public HTTPService() {
        super();
        getNetworkState().network = Network.HTTP;
    }

    public HTTPService(MessageProducer producer, ServiceStatusObserver observer) {
        super(Network.HTTP, producer, observer);
    }

    protected HTTPService(Network network, MessageProducer producer, ServiceStatusObserver observer) {
        super(network, producer, observer);
    }

    @Override
    public void handleDocument(Envelope envelope) {
        Route r = envelope.getDynamicRoutingSlip().getCurrentRoute();
        switch(r.getOperation()) {
            case OPERATION_SEND: {sendOut(envelope);break;}
            default: {deadLetter(envelope);break;}
        }
    }

    @Override
    public Boolean sendOut(Envelope e) {
        if(!isConnected() && !connect()) {
            e.getMessage().addErrorMessage("HTTP Client not connected and unable to connect.");
            send(e);
            return false;
        }
        Message m = e.getMessage();
        URL url = e.getURL();
        NetworkPeer dest;
        if(url==null && e.getRoute()!=null && e.getRoute() instanceof ExternalRoute) {
            dest = ((ExternalRoute)e.getRoute()).getDestination();
            if (dest.getId() != null) {
                try {
                    url = new URL("http://"+dest.getId());
                } catch (MalformedURLException malformedURLException) {
                    LOG.warning(malformedURLException.getLocalizedMessage());
                }
            }
        }
        if(url == null) {
            LOG.info("Must provide either a URL or External Route with destination Network Peer.");
            m.addErrorMessage("Must provide either a URL or External Route with destination Network Peer.");
            send(e);
            return false;
        } else {
            LOG.info("URL=" + url);
        }
        Map<String, Object> h = e.getHeaders();
        Map<String, String> hStr = new HashMap<>();
        if(h.containsKey(Envelope.HEADER_AUTHORIZATION) && h.get(Envelope.HEADER_AUTHORIZATION) != null) {
            hStr.put(Envelope.HEADER_AUTHORIZATION, (String) h.get(Envelope.HEADER_AUTHORIZATION));
        }
        if(h.containsKey(Envelope.HEADER_CONTENT_DISPOSITION) && h.get(Envelope.HEADER_CONTENT_DISPOSITION) != null) {
            hStr.put(Envelope.HEADER_CONTENT_DISPOSITION, (String) h.get(Envelope.HEADER_CONTENT_DISPOSITION));
        }
        if(h.containsKey(Envelope.HEADER_CONTENT_TYPE) && h.get(Envelope.HEADER_CONTENT_TYPE) != null) {
            hStr.put(Envelope.HEADER_CONTENT_TYPE, (String) h.get(Envelope.HEADER_CONTENT_TYPE));
        }
        if(h.containsKey(Envelope.HEADER_CONTENT_TRANSFER_ENCODING) && h.get(Envelope.HEADER_CONTENT_TRANSFER_ENCODING) != null) {
            hStr.put(Envelope.HEADER_CONTENT_TRANSFER_ENCODING, (String) h.get(Envelope.HEADER_CONTENT_TRANSFER_ENCODING));
        }
        if(h.containsKey(Envelope.HEADER_USER_AGENT) && h.get(Envelope.HEADER_USER_AGENT) != null) {
            hStr.put(Envelope.HEADER_USER_AGENT, (String) h.get(Envelope.HEADER_USER_AGENT));
        }

        ByteBuffer bodyBytes = null;
        CacheControl cacheControl = null;
        if (e.getMultipart() != null) {
            // handle file upload
            Multipart mp = e.getMultipart();
            hStr.put(Envelope.HEADER_CONTENT_TYPE, "multipart/form-data; boundary=" + mp.getBoundary());
            try {
                bodyBytes = ByteBuffer.wrap(mp.finish().getBytes());
            } catch (IOException e1) {
                e1.printStackTrace();
                // TODO: Provide error message
                LOG.warning("IOException caught while building HTTP body with multipart: " + e1.getLocalizedMessage());
                m.addErrorMessage("IOException caught while building HTTP body with multipart: " + e1.getLocalizedMessage());
                send(e);
                return false;
            }
            cacheControl = new CacheControl.Builder().noCache().build();
        }

        Headers headers = Headers.of(hStr);
        if(e.getRoute() instanceof ExternalRoute && ((ExternalRoute)e.getRoute()).getSendContentOnly()) {
            if (m instanceof DocumentMessage) {
                Object contentObj = e.getContent();
                if (contentObj instanceof String) {
                    if (bodyBytes == null) {
                        bodyBytes = ByteBuffer.wrap(((String) contentObj).getBytes());
                    } else {
                        bodyBytes.put(((String) contentObj).getBytes());
                    }
                } else if (contentObj instanceof byte[]) {
                    if (bodyBytes == null) {
                        bodyBytes = ByteBuffer.wrap((byte[]) contentObj);
                    } else {
                        bodyBytes.put((byte[]) contentObj);
                    }
                }
            } else {
                LOG.warning("Only DocumentMessages supported at this time.");
                e.addErrorMessage("Only DocumentMessages supported at this time.");
                send(e);
                return false;
            }
        } else {
            if (bodyBytes == null) {
                bodyBytes = ByteBuffer.wrap(e.toJSON().getBytes());
            } else {
                bodyBytes.put(e.toJSON().getBytes());
            }
        }

        RequestBody requestBody = null;
        if(bodyBytes != null) {
            requestBody = RequestBody.create(MediaType.parse((String) h.get(Envelope.HEADER_CONTENT_TYPE)), bodyBytes.array());
        }

        Request.Builder b = new Request.Builder().url(url);
        if(cacheControl != null)
            b = b.cacheControl(cacheControl);
        b = b.headers(headers);
        switch(e.getAction()) {
            case POST: {b = b.post(requestBody);break;}
            case PUT: {b = b.put(requestBody);break;}
            case DELETE: {b = (requestBody == null ? b.delete() : b.delete(requestBody));break;}
            case GET: {b = b.get();break;}
            default: {
                LOG.warning("Envelope.action must be set to ADD, UPDATE, REMOVE, or VIEW");
                m.addErrorMessage("Envelope.action must be set to ADD, UPDATE, REMOVE, or VIEW");
                send(e);
                return false;
            }
        }
        Request req = b.build();
        if(req == null) {
            LOG.warning("okhttp3 builder didn't build request.");
            m.addErrorMessage("okhttp3 builder didn't build request.");
            send(e);
            return false;
        }
        Response response = null;
        long start = 0L;
        long end = 0L;
        if(url.toString().startsWith("https:")) {
            LOG.info("Sending https request, host="+url.getHost());
            ensureHttpsStrongClient();
//            if(trustedHosts.contains(url.getHost())) {
            try {
//                    LOG.info("Trusted host, using compatible connection...");
                start = new Date().getTime();
                response = httpsStrongClient.newCall(req).execute();
                if(!response.isSuccessful()) {
                    end = new Date().getTime();
                    LOG.warning(response+" - code="+response.code());
                    m.addErrorMessage(response.code()+"");
                    handleFailure(start, end, m, url.toString());
                }
            } catch (IOException e1) {
                LOG.warning(e1.getLocalizedMessage());
                m.addErrorMessage(e1.getLocalizedMessage());
            }
        } else {
            LOG.info("Sending http request, host="+url.getHost());
            ensureHttpClient();
            try {
                start = new Date().getTime();
                response = httpClient.newCall(req).execute();
                if(!response.isSuccessful()) {
                    end = new Date().getTime();
                    LOG.warning("HTTP request not successful: "+response.code());
                    m.addErrorMessage(response.code()+"");
                    handleFailure(start, end, m, url.toString());
                }
            } catch (IOException e2) {
                LOG.warning(e2.getLocalizedMessage());
                m.addErrorMessage(e2.getLocalizedMessage());
            }
        }

        LOG.info("Received http response.");
        Headers responseHeaders = response.headers();
        for (int i = 0; i < responseHeaders.size(); i++) {
            LOG.info(responseHeaders.name(i) + ": " + responseHeaders.value(i));
        }
        ResponseBody responseBody = response.body();
        if(responseBody != null) {
            try {
                e.addContent(responseBody.bytes());
            } catch (IOException e1) {
                LOG.warning(e1.getLocalizedMessage());
            } finally {
                responseBody.close();
            }
//            LOG.info(new String((byte[])DLC.getContent(e)));
        } else {
            LOG.info("Body was null.");
        }
        return true;
    }

    protected void handleFailure(long start, long end, Message m, String url) {
        if(m!=null && m.getErrorMessages()!=null && m.getErrorMessages().size()>0) {
            for (String networkCode : m.getErrorMessages()) {
                LOG.warning("HTTP Error Code: " + networkCode);
                    switch (networkCode) {
                        case "403": {
                            // Forbidden
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-FORBIDDEN",
                                    "Received HTTP 403 response: Forbidden. HTTP Request considered blocked.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                        case "408": {
                            // Request Timeout
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-TIMEOUT",
                                    "Received HTTP 408 response: Request Timeout. HTTP Request considered blocked.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                        case "410": {
                            // Gone
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-GONE",
                                    "Received HTTP 410 response: Gone. HTTP Request considered blocked.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                        case "418": {
                            // I'm a teapot
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-TEAPOT",
                                    "Received HTTP 418 response: I'm a teapot. Might be blocking.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                        case "451": {
                            // Unavailable for legal reasons; your IP address might be denied access to the resource
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-LEGAL",
                                    "Received HTTP 451 response: unavailable for legal reasons. Your IP address might be denied access to the resource. HTTP Request considered blocked.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                        case "511": {
                            // Network Authentication Required
                            connectionReport(new NetworkConnectionReport(
                                    start,
                                    end,
                                    url,
                                    getNetworkState().network,
                                    networkCode,
                                    "BLOCKED-AUTHN",
                                    "Received HTTP 511 response: network authentication required. HTTP Request considered blocked.",
                                    getNetworkState().networkStatus));
                            break;
                        }
                    }
            }
        }
    }

    public boolean connect() {
        trustAllCerts = "true".equals(config.get(RA_HTTP_CLIENT_TRUST_ALL));
        try {
            if (trustAllCerts) {
                LOG.info("Initialize SSLContext with trustallcerts...");
                trustAllSSLContext = SSLContext.getInstance("TLS");
                trustAllSSLContext.init(null, trustAllTrustManager, new java.security.SecureRandom());
            }
        } catch (NoSuchAlgorithmException e) {
            LOG.warning(e.getLocalizedMessage());
            return false;
        } catch (KeyManagementException e) {
            LOG.warning(e.getLocalizedMessage());
            return false;
        }

        try {
            LOG.info("Setting up HTTP spec clients for http, https, and strong https....");
            httpSpec = new ConnectionSpec
                    .Builder(ConnectionSpec.CLEARTEXT)
                    .build();
            // httpClient itself is NOT built here - see ensureHttpClient()/ensureHttpsStrongClient():
            // OkHttpClient.Builder.build() was observed hanging unpredictably (seconds to indefinitely)
            // when called concurrently with other services' (I2P/BitcoinJ) own heavy startup-time
            // classloading/crypto init on a freshly booted container - reproduced with both the
            // CLEARTEXT (this) and TLS builders, so it isn't SSL/SecureRandom-specific. Deferring
            // every OkHttpClient build to first actual send avoids racing that startup burst.

            LOG.info("Setting https.protocols to system property...");
            System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2,TLSv1.3");

            httpsStrongSpec = new ConnectionSpec
                    .Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
                    .cipherSuites(
                            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
                    .build();
            // httpsStrongClient itself is NOT built here: it requires SSLContext.init(null, tm, null),
            // which reads a fresh SecureRandom seed on first use - fine in general, but on a freshly
            // booted container this can block for an unpredictable stretch (found by decompiling
            // OkHttpClient.Builder.build() and instrumenting each chained call - only .build() itself
            // never returned - while other services, e.g. I2P/BitcoinJ, are concurrently doing their
            // own heavy crypto init at startup). Most HTTPService consumers (e.g. Tor's SOCKS-proxied
            // hidden-service traffic) never actually send an https: URL, so building this eagerly
            // during connect() risked stalling startup for no benefit. Built lazily on first real
            // https: send instead - see ensureHttpsStrongClient(), called from sendOut().

        } catch (Exception e) {
            LOG.warning("Exception caught launching HTTP Client Service: " + e.getLocalizedMessage());
            updateNetworkStatus(NetworkStatus.ERROR);
            updateStatus(ServiceStatus.ERROR);
            return false;
        }
        updateNetworkStatus(NetworkStatus.CONNECTED);
        return true;
    }

    private synchronized void ensureHttpClient() {
        if (httpClient != null) return;
        LOG.info("Setting up http client" + (proxy == null ? "" : " with proxy") + "...");
        OkHttpClient.Builder b = new OkHttpClient.Builder()
                .protocols(Arrays.asList(Protocol.HTTP_1_1, Protocol.HTTP_2))
                .connectionSpecs(Collections.singletonList(httpSpec))
                .retryOnConnectionFailure(true)
                .followRedirects(true);
        if (proxy != null) b = b.proxy(proxy);
        httpClient = b.build();
    }

    private synchronized void ensureHttpsStrongClient() {
        if (httpsStrongClient != null) return;
        if (trustAllCerts) {
            LOG.info("Trust All Certs Strong HTTPS Compatible Client " + (proxy == null ? "" : "with Proxy ") + "building...");
            OkHttpClient.Builder b = new OkHttpClient.Builder()
                    .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                    .retryOnConnectionFailure(true)
                    .followSslRedirects(true)
                    .sslSocketFactory(trustAllSSLContext.getSocketFactory(), trustAllX509TrustManager)
                    .hostnameVerifier(trustAllHostnameVerifier);
            if (proxy != null) b = b.proxy(proxy);
            httpsStrongClient = b.build();
        } else {
            LOG.info("Standard Strong HTTPS Compatible Client " + (proxy == null ? "" : "with Proxy ") + "building...");
            OkHttpClient.Builder b = new OkHttpClient.Builder()
                    .connectionSpecs(Collections.singletonList(httpsStrongSpec))
                    .retryOnConnectionFailure(true)
                    .followSslRedirects(true);
            if (proxy != null) b = b.proxy(proxy);
            httpsStrongClient = b.build();
        }
    }

    public boolean disconnect() {
        // Tear down clients and their specs
        httpClient = null;
        httpSpec = null;
        httpsStrongClient = null;
        httpsStrongSpec = null;
        updateNetworkStatus(NetworkStatus.DISCONNECTED);
        return true;
    }

    public boolean isConnected() {
        return getNetworkState().networkStatus == NetworkStatus.CONNECTED;
    }

    private boolean determineAddrPortUsed(String addrPort) {
        for(String addrPortInt : servers.keySet()) {
            if(addrPortInt.equals(addrPort))
                return true;
        }
        return false;
    }

    private SessionHandler fileSessionHandler() {
        SessionHandler sessionHandler = new SessionHandler();
        SessionCache sessionCache = new NullSessionCache(sessionHandler);
        sessionCache.setSessionDataStore(fileSessionDataStore());
        sessionHandler.setSessionCache(sessionCache);
        sessionHandler.setHttpOnly(true);
        // make additional changes to your SessionHandler here
        return sessionHandler;
    }

    private FileSessionDataStore fileSessionDataStore() {
        FileSessionDataStore fileSessionDataStore = new FileSessionDataStore();
        File storeDir = new File(getServiceDirectory(), "http-session-store");
        storeDir.mkdir();
        fileSessionDataStore.setStoreDir(storeDir);
        return fileSessionDataStore;
    }

    protected boolean launch(String spec) {
        Server server = null;
        boolean launchOnStart = false;

        String[] params = spec.split(",");

        String name = params[0].trim();
        if (name == null) {
            LOG.severe("Name must be provided for HTTP server.");
            return false;
        }

        String typeParam = params[1].trim();
        if (typeParam == null) {
            LOG.severe("Listener type name must be provided for HTTP server.");
            return false;
        }

        String addrParam = params[2].trim();
        if (addrParam == null) {
            LOG.severe("Address must be provided for HTTP server with name=" + name);
            return false;
        }

        String portParam = params[3].trim();
        if (portParam == null) {
            LOG.severe("Port must be provided for HTTP server with name=" + name);
            return false;
        }
        int port = Integer.parseInt(portParam);
        String addrPort = addrParam+":"+portParam;
        if(determineAddrPortUsed(addrPort)) {
            LOG.severe(addrPort+" already in use.");
            return false;
        }

        String handlerParam = params[4].trim();
        if(handlerParam==null) {
            LOG.severe("Handler must be provided for HTTP server.");
            return false;
        }

        server = new Server(new InetSocketAddress(addrParam, port));
        servers.put(addrPort, server);

        HandlerCollection serverHandlers = new HandlerCollection();
        handlers.put(addrPort, serverHandlers);

        if (!"WEB".equals(typeParam) && !"SPA".equals(typeParam)) {
            serverHandlers.addHandler(fileSessionHandler());
            EnvelopeHandler handler = null;
            try {
                handler = (EnvelopeHandler) Class.forName(handlerParam).getConstructor().newInstance();
            } catch (Exception e) {
                LOG.severe(e.getLocalizedMessage());
                return false;
            }
            handler.setService(this);
            handler.setServerName(name);
            handler.setParameters(params);
            serverHandlers.addHandler(handler);
        } else {
            String launchOnStartParam = params[5].trim();
            if(launchOnStartParam == null) {
                LOG.severe("Launch on start (param 6) is required when using type=WEB or SPA");
                return false;
            }
            launchOnStart = "true".equals(launchOnStartParam);

            String resourceDirectory = params[6].trim();
            URL webDirURL = this.getClass().getClassLoader().getResource(resourceDirectory);
            ResourceHandler resourceHandler = new ResourceHandler();
            resourceHandler.setDirectoriesListed(false);
//                resourceHandler.setWelcomeFiles(new String[]{"index.html"});
            if (webDirURL != null) {
                resourceHandler.setResourceBase(webDirURL.toExternalForm());
            }

            boolean useWebSocket = params.length > 7 && "true".equals(params[7].trim());
            String webSocketAdapter = null;
            if (useWebSocket && params.length > 8) {
                webSocketAdapter = params[8].trim();
            }
            // TODO: Make Web Socket context path configurable

            ContextHandler wsContext = null;
            EnvelopeWebSocket webSocket = null;
            if (useWebSocket) {
                if (webSocketAdapter == null) {
                    // default
                    webSocket = new EnvelopeWebSocket(this);
                    LOG.info("No custom EnvelopWebSocket class provided; using generic one.");
                } else {
                    try {
                        webSocket = (EnvelopeWebSocket) Class.forName(webSocketAdapter).getConstructor().newInstance();
                        webSocket.setService(this);
                    } catch (InstantiationException e) {
                        LOG.severe("Unable to instantiate WebSocket of type: " + webSocketAdapter);
                        return false;
                    } catch (IllegalAccessException e) {
                        LOG.severe("Illegal Access caught when attempting to instantiate WebSocket of type: " + webSocketAdapter);
                        return false;
                    } catch (ClassNotFoundException e) {
                        LOG.severe("WebSocket class " + webSocketAdapter + " not found. Unable to instantiate.");
                        return false;
                    } catch (NoSuchMethodException e) {
                        LOG.severe(e.getLocalizedMessage());
                        return false;
                    } catch (InvocationTargetException e) {
                        LOG.severe(e.getLocalizedMessage());
                        return false;
                    }
                }
                if (webSocket == null) {
                    LOG.severe("WebSocket configured to be launched yet unable to instantiate.");
                    return false;
                } else {
                    EnvelopeWebSocket finalWebSocket = webSocket;
                    WebSocketHandler wsHandler = new WebSocketHandler() {
                        @Override
                        public void configure(WebSocketServletFactory factory) {
                            WebSocketPolicy policy = factory.getPolicy();
                            // set a one hour timeout
                            policy.setIdleTimeout(60 * 60 * 1000);
//                            policy.setAsyncWriteTimeout(60 * 1000);
//                            int maxSize = 100 * 1000000;
//                            policy.setMaxBinaryMessageSize(maxSize);
//                            policy.setMaxBinaryMessageBufferSize(maxSize);
//                            policy.setMaxTextMessageSize(maxSize);
//                            policy.setMaxTextMessageBufferSize(maxSize);

                            factory.setCreator(new WebSocketCreator() {
                                @Override
                                public Object createWebSocket(ServletUpgradeRequest req, ServletUpgradeResponse resp) {
                                    String query = req.getRequestURI().toString();
                                    if ((query == null) || (query.length() <= 0)) {
                                        try {
                                            resp.sendForbidden("Unspecified query");
                                        } catch (IOException e) {

                                        }
                                        return null;
                                    }
                                    return finalWebSocket;
                                }
                            });
                        }

                    };
                    wsContext = new ContextHandler();
                    // TODO: Make ws ra.http.server.EnvelopeJSONDataHandlerext path configurable
                    wsContext.setContextPath("/api/*");
                    wsContext.setHandler(wsHandler);
                }
            }

            serverHandlers.addHandler(fileSessionHandler());

            if ("SPA".equals(typeParam)) {
                serverHandlers.addHandler(new SPAHandler());
            }

            // TODO: Make data context path configurable
            ContextHandler dataContext = new ContextHandler();
            dataContext.setContextPath("/data/*");
            serverHandlers.addHandler(dataContext);
            serverHandlers.addHandler(resourceHandler);
            if (wsContext != null) {
                serverHandlers.addHandler(wsContext);
            }
            DefaultHandler defaultHandler = new DefaultHandler();
            serverHandlers.addHandler(defaultHandler);

//                if (dataHandlerStr != null) { // optional
//                    try {
//                        dataHandler = (EnvelopeHandler) Class.forName(dataHandlerStr).newInstance();
//                        dataHandler.setService(this);
//                        dataHandler.setServiceName(name);
//                        dataHandler.setParameters(params);
//                        dataContext.setHandler(dataHandler);
//                    } catch (InstantiationException e) {
//                        LOG.warning("Data Handler must be implementation of " + EnvelopeHandler.class.getName() + " to ensure asynchronous replies with Envelopes gets returned to calling thread.");
//                        return false;
//                    } catch (IllegalAccessException e) {
//                        LOG.warning("Getting an IllegalAccessException while attempting to instantiate data Handler implementation class " + dataHandlerStr + ". Launch application with appropriate read access.");
//                        return false;
//                    } catch (ClassNotFoundException e) {
//                        LOG.warning("Data Handler implementation " + dataHandlerStr + " not found. Ensure library included.");
//                        return false;
//                    }
//                }
        }

        server.setHandler(serverHandlers);
        LOG.info("Starting HTTP Server for " + name + " on "+addrParam+":" + port);
        try {
            server.start();
            LOG.finest(server.dump());
            LOG.info("HTTP Server for " + name + " started on "+addrParam+":" + port);
        } catch (Exception e1) {
            LOG.severe("Exception caught while starting HTTP Server for " + name + " on "+addrParam+" with port " + port + ": " + e1.getLocalizedMessage());
//            updateStatus(SensorStatus.ERROR);
            return false;
        }
        if (launchOnStart)
            BrowserUtil.launch(addrParam + ":" + port + "/");
//            if (webSocket != null) {
//                LOG.info("Subscribing WebSocket (" + webSocket.getClass().getName() + ") to TEXT notifications...");
        // Subscribe to Text notifications
//            Subscription subscription = new Subscription() {
//                @Override
//                public void notifyOfEvent(Envelope envelope) {
//                    webSocket.pushEnvelope(envelope);
//                }
//            };
//            SubscriptionRequest r = new SubscriptionRequest(EventMessage.Type.TEXT, subscription);
//            Envelope e = Envelope.documentFactory();
//            DLC.addData(SubscriptionRequest.class, r, e);
//            DLC.addRoute(NotificationService.class, NotificationService.OPERATION_SUBSCRIBE, e);
//            if (!sensor.sendIn(e)) {
//                sensor.updateStatus(SensorStatus.ERROR);
//                LOG.warning("Error sending subscription request to Notification Service for Web Socket.");
//                return false;
//            }
//            }
        return true;
    }

    @Override
    public boolean start(Properties p) {
        super.start(p);
        boolean success = true;
        LOG.info("Initializing client...");
        updateStatus(ServiceStatus.INITIALIZING);
        try {
            config = Config.loadFromClasspath(RA_HTTP_CLIENT_CONFIG, p, false);
        } catch (Exception e) {
            LOG.severe(e.getLocalizedMessage());
            return false;
        }
        config.put(RA_HTTP_CLIENT_DIR, getServiceDirectory().getAbsolutePath());

        LOG.info("Starting server(s)...");
        String serversConfig = config.getProperty(RA_HTTP_SERVER_CONFIGS);
        if(serversConfig!=null) {
            LOG.info("Building servers from configuration: " + serversConfig);
            String[] serversSpecs = serversConfig.split(":");
            LOG.info("Number of servers to start: " + serversSpecs.length);

            LOG.info("Starting...");
            updateStatus(ServiceStatus.STARTING);

            for (String spec : serversSpecs) {
                if(!launch(spec))
                    success = false;
            }
        }
        updateStatus(ServiceStatus.STARTING);
        if(!connect()) {
            success = false;
        }
        return success;
    }

    @Override
    public boolean pause() {
        LOG.warning("Pausing not supported.");
        return false;
    }

    @Override
    public boolean unpause() {
        LOG.warning("Pausing not supported.");
        return false;
    }

    @Override
    public boolean restart() {
        LOG.info("Restarting...");
        boolean success = true;
        if(!disconnect()) {
            success = false;
        }
        for(Server server : servers.values()) {
            try {
                server.stop();
            } catch (Exception e) {
                LOG.warning(e.getLocalizedMessage());
                success = false;
            }
        }
        for(Server server : servers.values()) {
            try {
                server.start();
            } catch (Exception e) {
                LOG.warning(e.getLocalizedMessage());
                success = false;
            }
        }
        if(!connect()) {
            success = false;
        }
        if(success)
            LOG.info("Restarted successfully.");
        else
            LOG.warning("Restart had problems.");
        return success;
    }

    @Override
    public boolean shutdown() {
        LOG.info("Shutting down...");
        updateNetworkStatus(NetworkStatus.DISCONNECTED);
        for(HandlerCollection handlerCollection : handlers.values()) {
            for(Handler handler : handlerCollection.getHandlers()) {
                if(handler instanceof EnvelopeHandler) {
                    ((EnvelopeHandler)handler).invalidateSessions();
                }
            }
        }
        for(Server server : servers.values()) {
            try {
                server.stop();
            } catch (Exception e) {
                LOG.warning(e.getLocalizedMessage());
            }
        }
        updateStatus(ServiceStatus.SHUTDOWN);
        LOG.info("Shutdown.");
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        return shutdown();
    }

}
