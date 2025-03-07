package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Constants.*;

public class CheckReflection {

    public static final int QUOTE_BYTE = 34;
    private static final String CANARY_PREFIX = "bnr";
    private static final String CANARY_SUFFIX = "rbn";
    private int bodyOffset;

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    IBurpExtenderCallbacks callbacks;
    private byte[] request;

    // Constructor for use by Aggressive class
    public CheckReflection(Settings settings, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
    }
    
    public String generateCacheBuster() {
        if (!settings.getUseCacheBuster()) {
            return null;
        }
        return "cb" + Long.toHexString(Double.doubleToLongBits(Math.random())).substring(0,8);
    }

    public void addCacheBustingHeaders(List<String> headers) {
        if (settings.getUseCacheBuster()) {
            // Keep this we will use it at some point
            // headers.add("X-oo: oo");
        }
    }

    public String addCacheBusterToUrl(String urlStr) {
        String cacheBuster = generateCacheBuster();
        if (cacheBuster == null) {
            return urlStr;
        }
        return urlStr + (urlStr.contains("?") ? "&" : "?") + cacheBuster + "=" + System.currentTimeMillis();
    }

    public String addCacheBusterToBody(String body) {
        String cacheBuster = generateCacheBuster();
        if (cacheBuster == null || body == null) {
            return body;
        }
        return body + (body.length() > 0 ? "&" : "") + cacheBuster + "=" + System.currentTimeMillis();
    }

    // Main constructor
    public CheckReflection(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks) {
        this.settings = settings;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.bodyOffset = helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset();
        this.request = iHttpRequestResponse.getRequest();
    }

    public List<Map> checkResponse() {
        String url = helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString();
        callbacks.printOutput("\n[URL] Testing " + url);
        
        // If no response available, fetch it first
        if (iHttpRequestResponse.getResponse() == null) {
            callbacks.printOutput("[URL] No response available, fetching URL first...");
            IHttpService httpService = iHttpRequestResponse.getHttpService();
            
            // Get the URL and add cache buster if enabled
            URL requestUrl = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
            String urlStr = requestUrl.toString();
            urlStr = addCacheBusterToUrl(urlStr);
            
            // Build request with headers
            List<String> headers = new ArrayList<>();
            try {
                URL parsedUrl = new URL(urlStr);
                headers.add("GET " + parsedUrl.getPath() + (parsedUrl.getQuery() != null ? "?" + parsedUrl.getQuery() : "") + " HTTP/1.1");
                headers.add("Host: " + requestUrl.getHost() + (requestUrl.getPort() == -1 ? "" : ":" + requestUrl.getPort()));
                addCacheBustingHeaders(headers);
            } catch (MalformedURLException e) {
                callbacks.printError("Error parsing URL: " + e.getMessage());
                return new ArrayList<>();
            }
            
            byte[] request = helpers.buildHttpMessage(headers, null);
            IHttpRequestResponse newReqRes = callbacks.makeHttpRequest(httpService, request);
            if (newReqRes != null && newReqRes.getResponse() != null) {
                iHttpRequestResponse = newReqRes;
            }
        }
        
        List<Map> reflectedParameters = new ArrayList<>();
        
        // Check parameters and cookies
        List<IParameter> parameters = helpers.analyzeRequest(iHttpRequestResponse).getParameters();
        checkParameters(parameters, reflectedParameters, url);
        
        // Check both request and response headers
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        
        List<String> requestHeaders = requestInfo.getHeaders();
        List<String> responseHeaders = responseInfo.getHeaders();
        
        callbacks.printOutput("[HEADERS] Checking " + requestHeaders.size() + " request headers");
        checkHeaders(requestHeaders, reflectedParameters, true, url);
        
        callbacks.printOutput("[HEADERS] Checking " + responseHeaders.size() + " response headers");
        checkHeaders(responseHeaders, reflectedParameters, false, url);
        
        // Only do aggressive testing if we found reflections and aggressive mode is enabled
        callbacks.printOutput("[DEBUG] Aggressive mode enabled: " + settings.getAggressiveMode());
        callbacks.printOutput("[DEBUG] Found " + reflectedParameters.size() + " reflected parameters");
        
        if (!reflectedParameters.isEmpty() && settings.getAggressiveMode()) {
            callbacks.printOutput("[+] Found reflections, starting aggressive testing...");
            for (Map param : reflectedParameters) {
                callbacks.printOutput("[DEBUG] Will test parameter: " + param.get(NAME) + 
                    " (Type: " + getTypeString(((Integer)param.get(TYPE)).byteValue()) + 
                    ", Reflected in: " + param.get(REFLECTED_IN) + ")");
            }
            Aggressive scan = new Aggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters);
            reflectedParameters = scan.scanReflectedParameters();
        } else {
            callbacks.printOutput(reflectedParameters.isEmpty() ? 
                "[-] No reflections found" : 
                "[-] Skipping aggressive testing (disabled in settings)");
        }

        // Add completion log
        callbacks.printOutput("[URL] Completed testing " + url + "\n");

        return reflectedParameters;
    }

    private void checkParameters(List<IParameter> parameters, List<Map> reflectedParameters, String url) {
        // First handle regular parameters and cookies from request
        for (IParameter parameter : parameters) {
            if (parameter.getType() == IParameter.PARAM_COOKIE) {
                // Handle cookies
                checkSingleParameter(parameter, reflectedParameters);
            }
            else if (parameter.getType() == IParameter.PARAM_URL || 
                     parameter.getType() == IParameter.PARAM_BODY) {
                // Handle regular parameters
                checkSingleParameter(parameter, reflectedParameters);
            }
        }
    }

    private void checkSingleParameter(IParameter parameter, List<Map> reflectedParameters) {
        String parameterType = getParameterTypeString(parameter);
        byte[] bytesOfParamValue = helpers.urlDecode(parameter.getValue().getBytes());
        
        callbacks.printOutput(String.format("[DEBUG] Testing %s '%s' with value: %s", 
            parameterType, 
            parameter.getName(), 
            parameter.getValue()));
            
        if (bytesOfParamValue.length == 0) {
            // For empty parameters, consider them reflected and test with canary
            String canaryValue = generateCanaryValue();
            callbacks.printOutput(String.format("[DEBUG] Empty parameter, testing with canary value: %s", canaryValue));
                
            // Create a copy of the original request before modifying
            byte[] canaryRequest = this.request.clone();
            
            // Get request info and prepare headers
            IRequestInfo requestInfo = helpers.analyzeRequest(canaryRequest);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());
            
            // Add cache control headers
            addCacheBustingHeaders(headers);
            
            // Update the parameter in the copied request
            canaryRequest = helpers.updateParameter(canaryRequest, 
                helpers.buildParameter(parameter.getName(), canaryValue, parameter.getType()));
            
            // Add cache buster to URL or body based on request type
            if (requestInfo.getMethod().equals("GET")) {
                String firstLine = headers.get(0);
                String url = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                url = addCacheBusterToUrl(url);
                headers.set(0, "GET " + url + " HTTP/1.1");
                canaryRequest = helpers.buildHttpMessage(headers, Arrays.copyOfRange(canaryRequest, requestInfo.getBodyOffset(), canaryRequest.length));
            } else {
                byte[] body = Arrays.copyOfRange(canaryRequest, requestInfo.getBodyOffset(), canaryRequest.length);
                String bodyStr = helpers.bytesToString(body);
                bodyStr = addCacheBusterToBody(bodyStr);
                canaryRequest = helpers.buildHttpMessage(headers, bodyStr.getBytes());
            }
            
            IHttpRequestResponse canaryResp = callbacks.makeHttpRequest(
                iHttpRequestResponse.getHttpService(),
                canaryRequest
            );

            List<int[]> canaryMatches = getMatches(canaryResp.getResponse(), canaryValue.getBytes());
            
            callbacks.printOutput(String.format("[DEBUG] Found %d canary matches for empty parameter", canaryMatches.size()));
            
            if (!canaryMatches.isEmpty()) {
                callbacks.printOutput(String.format("[CANARY CONFIRMED] %s '%s' reflection verified",
                    parameterType,
                    parameter.getName()));
                
                Map<String, Object> parameterDescription = new HashMap<>();
                parameterDescription.put(NAME, parameter.getName());
                parameterDescription.put(VALUE, parameter.getValue());
                parameterDescription.put(TYPE, Integer.valueOf(parameter.getType()));
                parameterDescription.put(MATCHES, canaryMatches);
                String reflectedIn = checkWhereReflectionPlaced(canaryMatches);
                parameterDescription.put(REFLECTED_IN, reflectedIn);
                parameterDescription.put(VALUE_START, parameter.getValueStart());
                parameterDescription.put(VALUE_END, parameter.getValueEnd());
                
                callbacks.printOutput("[DEBUG] Empty parameter reflection details:");
                callbacks.printOutput("[DEBUG] - Name: " + parameter.getName());
                callbacks.printOutput("[DEBUG] - Type: " + parameterType);
                callbacks.printOutput("[DEBUG] - Reflected in: " + reflectedIn);
                callbacks.printOutput("[DEBUG] - Number of matches: " + canaryMatches.size());
                
                reflectedParameters.add(parameterDescription);
            }
        } else {
            // For non-empty parameters, use existing logic
            List<int[]> originalMatches = getMatches(iHttpRequestResponse.getResponse(), bytesOfParamValue);
            
            callbacks.printOutput(String.format("[DEBUG] Found %d original matches for parameter %s", 
                originalMatches.size(),
                parameter.getName()));
            
            if (!originalMatches.isEmpty()) {
                String canaryValue = generateCanaryValue();
                callbacks.printOutput(String.format("[DEBUG] Testing with canary value: %s", canaryValue));
                
                // Create a copy of the original request before modifying
                byte[] canaryRequest = this.request.clone();
                
                // Add debug for request modification
                callbacks.printOutput("[DEBUG] Original request (hex): " + 
                    helpers.bytesToString(Arrays.copyOfRange(canaryRequest, parameter.getValueStart(), parameter.getValueEnd())));
                
                // Get request info and prepare headers
                IRequestInfo requestInfo = helpers.analyzeRequest(canaryRequest);
                List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                
                // Add cache busting headers
                addCacheBustingHeaders(headers);
                
                // Update the parameter in the copied request
                canaryRequest = helpers.updateParameter(canaryRequest, 
                    helpers.buildParameter(parameter.getName(), canaryValue, parameter.getType()));
                
                // Add cache buster to URL or body based on request type
                if (requestInfo.getMethod().equals("GET")) {
                    String firstLine = headers.get(0);
                    String url = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                    url = addCacheBusterToUrl(url);
                    headers.set(0, "GET " + url + " HTTP/1.1");
                    canaryRequest = helpers.buildHttpMessage(headers, Arrays.copyOfRange(canaryRequest, requestInfo.getBodyOffset(), canaryRequest.length));
                } else {
                    byte[] body = Arrays.copyOfRange(canaryRequest, requestInfo.getBodyOffset(), canaryRequest.length);
                    String bodyStr = helpers.bytesToString(body);
                    bodyStr = addCacheBusterToBody(bodyStr);
                    canaryRequest = helpers.buildHttpMessage(headers, bodyStr.getBytes());
                }
                
                callbacks.printOutput("[DEBUG] Modified request (hex): " + 
                    helpers.bytesToString(canaryRequest));
                
                IHttpRequestResponse canaryResp = callbacks.makeHttpRequest(
                    iHttpRequestResponse.getHttpService(),
                    canaryRequest
                );

                List<int[]> canaryMatches = getMatches(canaryResp.getResponse(), canaryValue.getBytes());
                
                callbacks.printOutput(String.format("[DEBUG] Found %d canary matches", canaryMatches.size()));
                
                if (!canaryMatches.isEmpty()) {
                    callbacks.printOutput(String.format("[CANARY CONFIRMED] %s '%s' reflection verified",
                        parameterType,
                        parameter.getName()));
                    
                    Map<String, Object> parameterDescription = new HashMap<>();
                    parameterDescription.put(NAME, parameter.getName());
                    parameterDescription.put(VALUE, parameter.getValue());
                    parameterDescription.put(TYPE, Integer.valueOf(parameter.getType()));
                    parameterDescription.put(MATCHES, originalMatches);
                    String reflectedIn = checkWhereReflectionPlaced(originalMatches);
                    parameterDescription.put(REFLECTED_IN, reflectedIn);
                    parameterDescription.put(VALUE_START, parameter.getValueStart());
                    parameterDescription.put(VALUE_END, parameter.getValueEnd());
                    
                    callbacks.printOutput("[DEBUG] Parameter reflection details:");
                    callbacks.printOutput("[DEBUG] - Name: " + parameter.getName());
                    callbacks.printOutput("[DEBUG] - Type: " + parameterType);
                    callbacks.printOutput("[DEBUG] - Reflected in: " + reflectedIn);
                    callbacks.printOutput("[DEBUG] - Number of matches: " + originalMatches.size());
                    
                    reflectedParameters.add(parameterDescription);
                }
            }
        }
    }

    private String getParameterTypeString(IParameter parameter) {
        return getTypeString(parameter.getType());
    }

    private String getTypeString(byte type) {
        switch (type) {
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_URL:
                return "URL Parameter";
            case IParameter.PARAM_BODY:
                return "Body Parameter";
            case IParameter.PARAM_JSON:
                return "JSON Parameter";
            case Constants.REQUEST_HEADER:
                return "Request Header";
            case Constants.RESPONSE_HEADER:
                return "Response Header";
            default:
                return "Parameter";
        }
    }

    private void checkHeaders(List<String> headers, List<Map> reflectedParameters, boolean isRequest, String url) {
        // Skip the first line for both request and response (HTTP/1.1 200 OK or GET /path HTTP/1.1)
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            String[] headerParts = header.split(":", 2);
            if (headerParts.length != 2) continue;
            
            String headerName = headerParts[0].trim();
            String headerValue = headerParts[1].trim();
            
            // Skip common headers that shouldn't be tested
            if (shouldSkipHeader(headerName)) continue;
            
            callbacks.printOutput(String.format("[HEADER CHECK] Testing %s header '%s' with value: %s",
                (isRequest ? "request" : "response"),
                headerName,
                headerValue));
            
            byte[] bytesOfHeaderValue = headerValue.getBytes();
            // For request headers, check for reflections in response
            if (isRequest) {
                if (bytesOfHeaderValue.length == 0) {
                    // For empty header values, consider them reflected and test with canary
                    String canaryValue = generateCanaryValue();
                    callbacks.printOutput(String.format("[CANARY TESTING] Testing request header '%s' with empty value using canary: %s",
                        headerName,
                        canaryValue));
                    
                    // Create modified request with canary value
                    List<String> modifiedHeaders = new ArrayList<>(headers);
                    for (int j = 0; j < modifiedHeaders.size(); j++) {
                        if (modifiedHeaders.get(j).startsWith(headerName + ":")) {
                            modifiedHeaders.set(j, headerName + ": " + canaryValue);
                            break;
                        }
                    }
                    
                    // Add cache busting
                    addCacheBustingHeaders(modifiedHeaders);
                    String firstLine = modifiedHeaders.get(0);
                    if (firstLine.startsWith("GET")) {
                        String urlPath = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                        urlPath = addCacheBusterToUrl(urlPath);
                        modifiedHeaders.set(0, "GET " + urlPath + " HTTP/1.1");
                    }
                    
                    byte[] canaryRequest = helpers.buildHttpMessage(modifiedHeaders, Arrays.copyOfRange(
                        iHttpRequestResponse.getRequest(),
                        helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                        iHttpRequestResponse.getRequest().length));
                    
                    IHttpRequestResponse canaryResp = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        canaryRequest);
                    
                    List<int[]> canaryMatches = getMatches(canaryResp.getResponse(), canaryValue.getBytes());
                    if (!canaryMatches.isEmpty()) {
                        // Only add if reflection is in body
                        String reflectedIn = checkWhereReflectionPlaced(canaryMatches);
                        if (!reflectedIn.equals(HEADERS)) {
                            // Create parameter description map
                            Map<String, Object> headerDescription = new HashMap<>();
                            headerDescription.put(NAME, headerName);
                            headerDescription.put(VALUE, headerValue);
                            headerDescription.put(TYPE, Integer.valueOf(Constants.REQUEST_HEADER));
                            headerDescription.put(MATCHES, canaryMatches);
                            headerDescription.put(REFLECTED_IN, reflectedIn);
                            
                            // Add header position information
                            String headerLine = headerName + ": " + headerValue;
                            int headerStart = helpers.bytesToString(request).indexOf(headerLine);
                            if (headerStart != -1) {
                                int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                                headerDescription.put(VALUE_START, valueStart);
                                headerDescription.put(VALUE_END, valueStart + headerValue.length());
                            }
                            
                            reflectedParameters.add(headerDescription);
                            callbacks.printOutput("[CANARY CONFIRMED] Empty request header '" + headerName + "' reflection verified in " + reflectedIn);
                        } else {
                            callbacks.printOutput("[CANARY CONFIRMED] Skipping empty request header '" + headerName + "' (reflection only in headers)");
                        }
                    }
                } else {
                    List<int[]> originalMatches = getMatches(iHttpRequestResponse.getResponse(), bytesOfHeaderValue);
                    if (!originalMatches.isEmpty()) {
                        callbacks.printOutput(String.format("[BASIC REFLECTION] Request header '%s' appears to be reflected", headerName));
                        
                        String canaryValue = generateCanaryValue();
                        callbacks.printOutput(String.format("[CANARY TESTING] Testing request header '%s' with value: %s",
                            headerName,
                            canaryValue));
                        
                        // Create modified request with canary value
                        List<String> modifiedHeaders = new ArrayList<>(headers);
                        for (int j = 0; j < modifiedHeaders.size(); j++) {
                            if (modifiedHeaders.get(j).startsWith(headerName + ":")) {
                                modifiedHeaders.set(j, headerName + ": " + canaryValue);
                                break;
                            }
                        }
                        
                        // Add cache busting
                        addCacheBustingHeaders(modifiedHeaders);
                        String firstLine = modifiedHeaders.get(0);
                        if (firstLine.startsWith("GET")) {
                            String urlPath = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                            urlPath = addCacheBusterToUrl(urlPath);
                            modifiedHeaders.set(0, "GET " + urlPath + " HTTP/1.1");
                        }
                        
                        byte[] canaryRequest = helpers.buildHttpMessage(modifiedHeaders, Arrays.copyOfRange(
                            iHttpRequestResponse.getRequest(),
                            helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                            iHttpRequestResponse.getRequest().length));
                        
                        IHttpRequestResponse canaryResp = callbacks.makeHttpRequest(
                            iHttpRequestResponse.getHttpService(),
                            canaryRequest);
                        
                        List<int[]> canaryMatches = getMatches(canaryResp.getResponse(), canaryValue.getBytes());
                        if (!canaryMatches.isEmpty()) {
                            callbacks.printOutput("[DEBUG] Found canary matches:");
                            for (int[] match : canaryMatches) {
                                callbacks.printOutput(String.format("[DEBUG] Match at positions %d-%d: %s", 
                                    match[0], 
                                    match[1],
                                    helpers.bytesToString(Arrays.copyOfRange(canaryResp.getResponse(), match[0], match[1]))));
                            }
                            
                            // Only add if reflection is in body
                            String reflectedIn = checkWhereReflectionPlaced(originalMatches);
                            if (!reflectedIn.equals(HEADERS)) {
                                // Create parameter description map
                                Map<String, Object> headerDescription = new HashMap<>();
                                headerDescription.put(NAME, headerName);
                                headerDescription.put(VALUE, headerValue);
                                headerDescription.put(TYPE, Integer.valueOf(Constants.REQUEST_HEADER));
                                headerDescription.put(MATCHES, originalMatches);
                                headerDescription.put(REFLECTED_IN, reflectedIn);
                                
                                // Add header position information
                                String headerLine = headerName + ": " + headerValue;
                                int headerStart = helpers.bytesToString(request).indexOf(headerLine);
                                if (headerStart != -1) {
                                    int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                                    headerDescription.put(VALUE_START, valueStart);
                                    headerDescription.put(VALUE_END, valueStart + headerValue.length());
                                }
                                
                                reflectedParameters.add(headerDescription);
                                callbacks.printOutput("[CANARY CONFIRMED] Request header '" + headerName + "' reflection verified in " + reflectedIn);
                            } else {
                                callbacks.printOutput("[CANARY CONFIRMED] Skipping request header '" + headerName + "' (reflection only in headers)");
                            }
                            callbacks.printOutput("[CANARY CONFIRMED] Request header '" + headerName + "' reflection verified");
                        } else {
                            callbacks.printOutput("[CANARY FAILED] Request header '" + headerName + "' reflection could not be verified");
                        }
                    }
                }
            }
            // For response headers
            List<int[]> requestHeaderMatches = new ArrayList<>();
            if (!isRequest) {
                if (bytesOfHeaderValue.length == 0) {
                    // For empty header values, consider them reflected and test with canary
                    String canaryValue = generateCanaryValue();
                    callbacks.printOutput(String.format("[CANARY CHECK] Testing response header '%s' with empty value using canary: %s",
                        headerName,
                        canaryValue));
                    
                    // Create request with canary value
                    List<String> canaryHeaders = new ArrayList<>(helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getHeaders());
                    // Check if header already exists
                    boolean headerExists = false;
                    for (int j = 0; j < canaryHeaders.size(); j++) {
                        if (canaryHeaders.get(j).toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                            canaryHeaders.set(j, headerName + ": " + canaryValue);
                            headerExists = true;
                            break;
                        }
                    }
                    if (!headerExists) {
                        canaryHeaders.add(headerName + ": " + canaryValue);
                    }
                    
                    byte[] canaryBody = Arrays.copyOfRange(
                        iHttpRequestResponse.getRequest(),
                        helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                        iHttpRequestResponse.getRequest().length);
                    
                    // Add cache busting
                    addCacheBustingHeaders(canaryHeaders);
                    String firstLine = canaryHeaders.get(0);
                    if (firstLine.startsWith("GET")) {
                        String urlPath = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                        urlPath = addCacheBusterToUrl(urlPath);
                        canaryHeaders.set(0, "GET " + urlPath + " HTTP/1.1");
                    }
                    
                    byte[] canaryRequest = helpers.buildHttpMessage(canaryHeaders, canaryBody);
                    
                    // Send canary request and check response
                    IHttpRequestResponse canaryResponse = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        canaryRequest);
                    
                    List<int[]> canaryMatches = getMatches(canaryResponse.getResponse(), canaryValue.getBytes());
                    
                    if (!canaryMatches.isEmpty()) {
                        callbacks.printOutput("[CANARY CONFIRMED] Response header reflection verified with canary value");
                        
                        // Create parameter description map with proper TYPE field
                        Map<String, Object> headerDescription = new HashMap<>();
                        headerDescription.put(NAME, headerName);
                        headerDescription.put(VALUE, headerValue);
                        headerDescription.put(TYPE, Integer.valueOf(Constants.REQUEST_HEADER)); // Use REQUEST_HEADER type since we're testing it as a request header
                        headerDescription.put(MATCHES, canaryMatches);
                        headerDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(canaryMatches));
                        
                        // Add header position information
                        String headerLine = headerName + ": " + headerValue;
                        int headerStart = helpers.bytesToString(request).indexOf(headerLine);
                        if (headerStart != -1) {
                            int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                            headerDescription.put(VALUE_START, valueStart);
                            headerDescription.put(VALUE_END, valueStart + headerValue.length());
                        }
                        
                        reflectedParameters.add(headerDescription);
                        callbacks.printOutput("[CANARY CONFIRMED] Empty response header '" + headerName + "' reflection verified");
                    }
                } else {
                    // For non-empty header values, use existing logic
                    // First test with canary value
                    String canaryValue = generateCanaryValue();
                    callbacks.printOutput(String.format("[CANARY CHECK] Testing response header '%s' with canary value: %s", 
                        headerName, 
                        canaryValue));
                    
                    // Create request with canary value
                    List<String> canaryHeaders = new ArrayList<>(helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getHeaders());
                    canaryHeaders.add(headerName + ": " + canaryValue);
                    
                    byte[] canaryBody = Arrays.copyOfRange(
                        iHttpRequestResponse.getRequest(),
                        helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                        iHttpRequestResponse.getRequest().length);
                    
                    // Add cache busting
                    addCacheBustingHeaders(canaryHeaders);
                    String firstLine = canaryHeaders.get(0);
                    if (firstLine.startsWith("GET")) {
                        String urlPath = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                        urlPath = addCacheBusterToUrl(urlPath);
                        canaryHeaders.set(0, "GET " + urlPath + " HTTP/1.1");
                    }
                    
                    byte[] canaryRequest = helpers.buildHttpMessage(canaryHeaders, canaryBody);
                    
                    // Send canary request and check response
                    IHttpRequestResponse canaryResponse = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        canaryRequest);
                    
                    List<int[]> canaryMatches = getMatches(canaryResponse.getResponse(), canaryValue.getBytes());
                    
                    if (!canaryMatches.isEmpty()) {
                        callbacks.printOutput("[CANARY CONFIRMED] Response header reflection verified with canary value");
                        
                        // Now test with original value
                        callbacks.printOutput(String.format("[HEADER CHECK] Testing response header '%s' with original value", headerName));
                        
                        List<String> requestHeaders = helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getHeaders();
                        List<String> newHeaders = new ArrayList<>(requestHeaders);
                        // Check if header already exists
                        boolean headerExists = false;
                        for (int k = 0; k < newHeaders.size(); k++) {
                            if (newHeaders.get(k).toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                                newHeaders.set(k, headerName + ": " + headerValue);
                                headerExists = true;
                                break;
                            }
                        }
                        if (!headerExists) {
                            newHeaders.add(headerName + ": " + headerValue);
                        }
                        
                        byte[] body = Arrays.copyOfRange(
                            iHttpRequestResponse.getRequest(),
                            helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                            iHttpRequestResponse.getRequest().length);
                        
                        // Add cache busting
                        addCacheBustingHeaders(newHeaders);
                        firstLine = newHeaders.get(0);
                        if (firstLine.startsWith("GET")) {
                            String urlPath = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                            urlPath = addCacheBusterToUrl(urlPath);
                            newHeaders.set(0, "GET " + urlPath + " HTTP/1.1");
                        }
                        
                        byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);
                        
                        // Send request and check for reflections
                        IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                            iHttpRequestResponse.getHttpService(),
                            newRequest);
                        
                        requestHeaderMatches = getMatches(testResponse.getResponse(), bytesOfHeaderValue);
                        callbacks.printOutput(String.format("[DEBUG] Found %d matches with original value", requestHeaderMatches.size()));
                        
                        if (!requestHeaderMatches.isEmpty()) {
                            callbacks.printOutput("[DEBUG] Match positions:");
                            for (int[] match : requestHeaderMatches) {
                                callbacks.printOutput(String.format("[DEBUG] Match at positions %d-%d: %s", 
                                    match[0], 
                                    match[1],
                                    helpers.bytesToString(Arrays.copyOfRange(testResponse.getResponse(), match[0], match[1]))));
                            }
                            callbacks.printOutput(String.format("[HEADER CHECK] Response header '%s' reflected when used as request header", headerName));
                        
                            // Create parameter description map with proper TYPE field
                            Map<String, Object> headerDescription = new HashMap<>();
                            headerDescription.put(NAME, headerName);
                            headerDescription.put(VALUE, headerValue);
                            headerDescription.put(TYPE, Integer.valueOf(Constants.REQUEST_HEADER)); // Use REQUEST_HEADER type since we're testing it as a request header
                            headerDescription.put(MATCHES, requestHeaderMatches);
                            headerDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(requestHeaderMatches));
                            
                            // Add header position information
                            String headerLine = headerName + ": " + headerValue;
                            int headerStart = helpers.bytesToString(newRequest).indexOf(headerLine);
                            if (headerStart != -1) {
                                int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                                headerDescription.put(VALUE_START, valueStart);
                                headerDescription.put(VALUE_END, valueStart + headerValue.length());
                            }
                            
                            reflectedParameters.add(headerDescription);
                            continue; // Skip original response header check since we found it as request header
                        } else {
                            callbacks.printOutput("[DEBUG] Original value not reflected despite canary success");
                        }
                    } else {
                        callbacks.printOutput("[CANARY FAILED] Response header reflection could not be verified with canary value");
                    }
                }
                
                // For response headers, do canary testing if initial test found reflections
                if (!isRequest && !requestHeaderMatches.isEmpty()) {
                    // For response headers, verify canary when used as request header
                    String canaryValue = generateCanaryValue();
                    callbacks.printOutput(String.format("[CANARY TESTING] Testing response header '%s' as request header with value: %s",
                        headerName,
                        canaryValue));
                    
                    List<String> canaryRequestHeaders = helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getHeaders();
                    List<String> newCanaryHeaders = new ArrayList<>(canaryRequestHeaders);
                    newCanaryHeaders.add(headerName + ": " + canaryValue);
                    
                    byte[] canaryBody = Arrays.copyOfRange(
                        iHttpRequestResponse.getRequest(),
                        helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                        iHttpRequestResponse.getRequest().length);
                    
                    byte[] newCanaryRequest = helpers.buildHttpMessage(newCanaryHeaders, canaryBody);
                    IHttpRequestResponse canaryHeaderResp = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        newCanaryRequest);
                    
                    // Log full request and response for debugging
                    callbacks.printOutput("[DEBUG] Canary request:");
                    callbacks.printOutput(helpers.bytesToString(newCanaryRequest));
                    callbacks.printOutput("[DEBUG] Canary response:");
                    callbacks.printOutput(helpers.bytesToString(canaryHeaderResp.getResponse()));
                    
                    List<int[]> canaryMatches = getMatches(canaryHeaderResp.getResponse(), canaryValue.getBytes());
                    if (!canaryMatches.isEmpty()) {
                        callbacks.printOutput("[DEBUG] Found canary matches when used as request header:");
                        for (int[] match : canaryMatches) {
                            callbacks.printOutput(String.format("[DEBUG] Match at positions %d-%d: %s", 
                                match[0], 
                                match[1],
                                helpers.bytesToString(Arrays.copyOfRange(canaryHeaderResp.getResponse(), match[0], match[1]))));
                        }
                        
                        // Create parameter description map with proper TYPE field
                        Map<String, Object> headerDescription = new HashMap<>();
                        headerDescription.put(NAME, headerName);
                        headerDescription.put(VALUE, headerValue);
                        headerDescription.put(TYPE, Integer.valueOf(Constants.REQUEST_HEADER)); // Use REQUEST_HEADER type since we're testing it as a request header
                        headerDescription.put(MATCHES, canaryMatches);
                        headerDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(canaryMatches));
                        
                        // Add header position information
                        String headerLine = headerName + ": " + headerValue;
                        int headerStart = helpers.bytesToString(newCanaryRequest).indexOf(headerLine);
                        if (headerStart != -1) {
                            int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                            headerDescription.put(VALUE_START, valueStart);
                            headerDescription.put(VALUE_END, valueStart + headerValue.length());
                        }
                        
                        reflectedParameters.add(headerDescription);
                        callbacks.printOutput("[CANARY CONFIRMED] Response header '" + headerName + "' reflection verified when used as request header");
                    } else {
                        callbacks.printOutput("[CANARY FAILED] Response header '" + headerName + "' reflection could not be verified");
                    }
                }
            }
        }
    }

    private boolean shouldSkipHeader(String headerName) {
        // List of headers that shouldn't be tested
        String[] skipHeaders = {
            // Standard headers that shouldn't be tested
            "Content-Length",
            "Content-Type",
            "Date",
            "Expires",
            "Last-Modified",
            // Connection-related headers
            "Keep-Alive",
            "Connection",
            "Trailer",
            "Transfer-Encoding",
            // Server info headers
            "Server",
            "Server-Timing",
            // Security headers
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode", 
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Pragma",
            "Priority"
        };
        
        return Arrays.asList(skipHeaders).contains(headerName);
    }

    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        for(int[] matches : listOfMatches) {
            if(matches[0] >= bodyOffset) {
                return BODY;
            }
        }
        return HEADERS; // If no matches in body, must be in headers
    }

    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();
        
        // Get body offset to only search in body
        int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
        
        // Only search in response body
        int start = bodyOffset;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    private String generateCanaryValue() {
        // Generate a random 6 char string
        String randomStr = Long.toHexString(Double.doubleToLongBits(Math.random())).substring(0,6);
        return "bnr" + randomStr + "rbn";
    }
}

class Aggressive
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private List<Map> reflectedParameters;
    private IHttpRequestResponse baseRequestResponse;
    private String host;
    private int port;
    private static final String PAYLOAD_GREP = "qzx";
    private static final String PAYLOAD = "<\"'`";
    private static final String PAYLOAD_JSON = "<\\\"'`";
    private Pattern pattern;
    private Settings settings;
    private CheckReflection checkReflection;

    Aggressive(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, List<Map> reflectedParameters) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.reflectedParameters = reflectedParameters;
        this.baseRequestResponse = baseRequestResponse;
        this.host = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        this.port = helpers.analyzeRequest(baseRequestResponse).getUrl().getPort();
        // Pattern for matching individual special characters between markers
        this.pattern = Pattern.compile(PAYLOAD_GREP + "([<\"'`])" + PAYLOAD_GREP);
        // // OLD ONE KEEP FOR NOW
        // this.pattern = Pattern.compile(PAYLOAD_GREP + "([_%&;<\"'`#\\\\0-9a-z]{1,15}?)" + PAYLOAD_GREP);
        this.settings = settings;
        this.checkReflection = new CheckReflection(settings, helpers, callbacks);
    }

    public List<Map> scanReflectedParameters(){
        String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        String testRequest = "",
            symbols = "";
        
        for (Map param : reflectedParameters) {
            String paramName = (String)param.get(NAME);
            String paramType = getTypeString(((Integer)param.get(TYPE)).byteValue());
            callbacks.printOutput("[SPECIAL CHARS] Testing " + paramType + " '" + paramName + "' at " + url);
            // Reset reflected special chars for each parameter
            List<String> reflectedSpecialChars = new ArrayList<>();
            
            callbacks.printOutput("[DEBUG] Parameter details:");
            callbacks.printOutput("[DEBUG] - Type: " + paramType);
            callbacks.printOutput("[DEBUG] - Value: " + param.get(VALUE));
            callbacks.printOutput("[DEBUG] - Reflected in: " + param.get(REFLECTED_IN));
            callbacks.printOutput("[DEBUG] - Value start: " + param.get(VALUE_START));
            callbacks.printOutput("[DEBUG] - Value end: " + param.get(VALUE_END));
            
            if(param.get(REFLECTED_IN).equals(HEADERS)) {
                callbacks.printOutput("[SPECIAL CHARS] Skipping " + paramType + " reflection for '" + paramName + 
                    "' (header reflections are not tested for XSS)");
                continue;
            }
            
            callbacks.printOutput("[DEBUG] Preparing test request for parameter: " + paramName);
            testRequest = prepareRequest(param);
            callbacks.printOutput("[DEBUG] Test request prepared: " + testRequest.length() + " bytes");
            symbols = checkResponse(testRequest, param, reflectedSpecialChars);
            
            callbacks.printOutput("[DEBUG-CONTEXT] Parameter: " + paramName);
            callbacks.printOutput("[DEBUG-CONTEXT] Type: " + paramType);
            callbacks.printOutput("[DEBUG-CONTEXT] Reflected special chars: " + reflectedSpecialChars);
            callbacks.printOutput("[DEBUG-CONTEXT] Context symbols result: " + symbols);
            callbacks.printOutput("[DEBUG-CONTEXT] Reflected in: " + param.get(REFLECTED_IN));
            
            // Always add reflected special chars if we found any
            if (!reflectedSpecialChars.isEmpty()) {
                param.put("reflectedSpecialChars", new ArrayList<>(reflectedSpecialChars));
            }
            
            if (!symbols.equals("")) {
                callbacks.printOutput("[SPECIAL CHARS] " + paramType + " '" + paramName + "' is vulnerable to: " + symbols);
                param.put(VULNERABLE, symbols + "\n");
            } else {
                callbacks.printOutput("[SPECIAL CHARS] No special character vulnerabilities found for " + paramType + " '" + paramName + "'");
            }
        }
        return reflectedParameters;
    }

    private String getTypeString(byte type) {
        switch (type) {
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_URL:
                return "URL Parameter";
            case IParameter.PARAM_BODY:
                return "Body Parameter";
            case IParameter.PARAM_JSON:
                return "JSON Parameter";
            case Constants.REQUEST_HEADER:
                return "Request Header";
            case Constants.RESPONSE_HEADER:
                return "Response Header";
            default:
                return "Parameter";
        }
    }

    public static String prepareReflectedPayload(String value) {
        return value.replaceAll("[^<\"'`\\\\]", "").replaceAll("(\\\\\"|\\\\')", "").replaceAll("[\\\\]", "");
    }

    private String checkResponse(String testRequest, Map param, List<String> reflectedSpecialChars) {
        String reflectedPayloadValue = "",
                symbols = "";
        int bodyOffset = -1;
        try {
            Map<String, ArrayList<int[]>> reflectionMap = new HashMap<>();
            String lastResponse = null;
            
            // Use the parameter being tested
            Map<String, Object> parameter = param;
            byte type = ((Integer)parameter.get(TYPE)).byteValue();
            callbacks.printOutput("[DEBUG-HEADER] Parameter type: " + type);
            callbacks.printOutput("[DEBUG-HEADER] Parameter name: " + parameter.get(NAME));
            callbacks.printOutput("[DEBUG-HEADER] Testing special chars: " + (parameter.get(TYPE).equals(IParameter.PARAM_JSON) ? PAYLOAD_JSON : PAYLOAD));
            
            String chars = parameter.get(TYPE).equals(IParameter.PARAM_JSON) ? PAYLOAD_JSON : PAYLOAD;
            
            // Test each special character individually
            callbacks.printOutput("[DEBUG-HEADER] Starting special character tests...");
            for (char c : chars.toCharArray()) {
                callbacks.printOutput("[DEBUG-HEADER] Testing character: " + c);
                String singleCharRequest = prepareRequest(parameter, String.valueOf(c));
                
                // Log the request we're sending
                callbacks.printOutput("[DEBUG-REQUEST] Sending request:");
                callbacks.printOutput(singleCharRequest);
                
                IHttpRequestResponse responseObject = this.callbacks.makeHttpRequest(
                        this.baseRequestResponse.getHttpService(),
                        singleCharRequest.getBytes()
                );
                String response = helpers.bytesToString(responseObject.getResponse());
                bodyOffset = helpers.analyzeResponse(responseObject.getResponse()).getBodyOffset();
                
                // Log response details
                callbacks.printOutput("[DEBUG-PAYLOAD] Response details:");
                callbacks.printOutput("[DEBUG-PAYLOAD] - Length: " + response.length());
                callbacks.printOutput("[DEBUG-PAYLOAD] - Body offset: " + bodyOffset);
                
                // Get response body and headers
                String headers = response.substring(0, bodyOffset);
                String body = response.substring(bodyOffset);
                
                // Log full response structure
                callbacks.printOutput("[DEBUG-PAYLOAD] Response structure:");
                callbacks.printOutput("[DEBUG-PAYLOAD] Headers (" + headers.length() + " bytes):");
                String[] headerLines = headers.split("\r\n");
                for (String line : headerLines) {
                    callbacks.printOutput("[DEBUG-PAYLOAD] " + line);
                }
                callbacks.printOutput("[DEBUG-PAYLOAD] Body (" + body.length() + " bytes):");
                callbacks.printOutput("[DEBUG-PAYLOAD] First 200 chars: " + body.substring(0, Math.min(200, body.length())));
                
                // Search for our markers and special char in headers and body separately
                callbacks.printOutput("\n[DEBUG-PAYLOAD] Searching in headers:");
                int headerMarkerIndex = headers.indexOf(PAYLOAD_GREP);
                while (headerMarkerIndex != -1) {
                    int contextStart = Math.max(0, headerMarkerIndex - 20);
                    int contextEnd = Math.min(headers.length(), headerMarkerIndex + PAYLOAD_GREP.length() + 20);
                    String context = headers.substring(contextStart, contextEnd);
                    
                    callbacks.printOutput("[DEBUG-PAYLOAD] Found marker at offset " + headerMarkerIndex + ":");
                    callbacks.printOutput("[DEBUG-PAYLOAD] - Context: ..." + context + "...");
                    callbacks.printOutput("[DEBUG-PAYLOAD] - Bytes: " + Arrays.toString(context.getBytes()));
                    
                    // Look for special char near this marker
                    int specialCharPos = headers.indexOf(c, headerMarkerIndex);
                    if (specialCharPos != -1 && specialCharPos < headerMarkerIndex + 20) {
                        callbacks.printOutput("[DEBUG-PAYLOAD] - Found special char '" + c + "' at offset " + specialCharPos);
                        callbacks.printOutput("[DEBUG-PAYLOAD] - Distance from marker: " + (specialCharPos - headerMarkerIndex) + " chars");
                    }
                    
                    headerMarkerIndex = headers.indexOf(PAYLOAD_GREP, headerMarkerIndex + 1);
                }
                
                callbacks.printOutput("\n[DEBUG-PAYLOAD] Searching in body:");
                int bodyMarkerIndex = body.indexOf(PAYLOAD_GREP);
                while (bodyMarkerIndex != -1) {
                    int contextStart = Math.max(0, bodyMarkerIndex - 20);
                    int contextEnd = Math.min(body.length(), bodyMarkerIndex + PAYLOAD_GREP.length() + 20);
                    String context = body.substring(contextStart, contextEnd);
                    
                    callbacks.printOutput("[DEBUG-PAYLOAD] Found marker at offset " + bodyMarkerIndex + ":");
                    callbacks.printOutput("[DEBUG-PAYLOAD] - Context: ..." + context + "...");
                    callbacks.printOutput("[DEBUG-PAYLOAD] - Bytes: " + Arrays.toString(context.getBytes()));
                    
                    // Look for special char near this marker
                    int specialCharPos = body.indexOf(c, bodyMarkerIndex);
                    if (specialCharPos != -1 && specialCharPos < bodyMarkerIndex + 20) {
                        callbacks.printOutput("[DEBUG-PAYLOAD] - Found special char '" + c + "' at offset " + specialCharPos);
                        callbacks.printOutput("[DEBUG-PAYLOAD] - Distance from marker: " + (specialCharPos - bodyMarkerIndex) + " chars");
                    }
                    
                    bodyMarkerIndex = body.indexOf(PAYLOAD_GREP, bodyMarkerIndex + 1);
                }

                // Look for reflection of this specific character
                Pattern singleCharPattern = Pattern.compile(PAYLOAD_GREP + "([^" + PAYLOAD_GREP + "]*)" + PAYLOAD_GREP);
                Matcher matcher = singleCharPattern.matcher(response);
                ArrayList<int[]> payloadIndexes = new ArrayList<>();
                boolean charReflected = false;
                
                while (matcher.find()) {
                    String matchedContent = matcher.group();
                    String between = matchedContent.substring(PAYLOAD_GREP.length(), matchedContent.length() - PAYLOAD_GREP.length());
                    
                    // Get some context around the match
                    int contextStart = Math.max(0, matcher.start() - 20);
                    int contextEnd = Math.min(response.length(), matcher.end() + 20);
                    String context = response.substring(contextStart, contextEnd);
                    
                    callbacks.printOutput("[DEBUG-PAYLOAD] Found match: " + matchedContent);
                    callbacks.printOutput("[DEBUG-PAYLOAD] Content between markers: " + between);
                    callbacks.printOutput("[DEBUG-PAYLOAD] Context: ..." + context + "...");
                    
                    // Check if the special character was actually reflected (not filtered/modified)
                    if (between.equals(String.valueOf(c))) {
                        callbacks.printOutput("[DEBUG-PAYLOAD] Character '" + c + "' was successfully reflected for " + parameter.get(NAME));
                        payloadIndexes.add(new int[]{matcher.start() - bodyOffset, matcher.end() - bodyOffset});
                        charReflected = true;
                    } else {
                        if (between.isEmpty()) {
                            callbacks.printOutput("[DEBUG-PAYLOAD] Character '" + c + "' was removed by server");
                        } else if (between.length() > 1) {
                            callbacks.printOutput("[DEBUG-PAYLOAD] Character '" + c + "' was encoded/expanded to: " + between);
                        } else {
                            callbacks.printOutput("[DEBUG-PAYLOAD] Character '" + c + "' was changed to: " + between);
                        }
                    }
                }
                
                // Only track special chars that were actually reflected unchanged
                if (charReflected) {
                    reflectedSpecialChars.add(String.valueOf(c));
                    callbacks.printOutput("[DEBUG-PAYLOAD-FOUND] Added special char to tracking: " + c);
                    reflectionMap.put(String.valueOf(c), payloadIndexes);
                }
            }

            if (reflectionMap.isEmpty()) {
                callbacks.printOutput("[DEBUG-PAYLOAD] No special characters reflected");
                return "";
            }

            // Get a combined response for context analysis
            String combinedPayload = String.join("", reflectionMap.keySet());
            callbacks.printOutput("[DEBUG-CONTEXT] Get a combined response for context analysis because easier for now");
            String response = helpers.bytesToString(this.callbacks.makeHttpRequest(
                    this.baseRequestResponse.getHttpService(),
                    prepareRequest(parameter, combinedPayload).getBytes()
            ).getResponse());
            
            bodyOffset = helpers.analyzeResponse(response.getBytes()).getBodyOffset();
            
            if (settings.getCheckContext() && bodyOffset != response.length()) {
                // Only do context analysis if we actually found reflected special chars
                if (!reflectedSpecialChars.isEmpty()) {
                    // Get parameter info from the Map
                    String paramName = (String) param.get(NAME);
                    
                    // Add debug logging for context analysis
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] Starting context analysis for " + 
                        "" + " '" + paramName + "'");
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] Special chars found for " + 
                        paramName + ": " + reflectedSpecialChars);
                    
                    // Combine all payload indexes for context analysis
                    ArrayList<int[]> allIndexes = new ArrayList<>();
                    reflectionMap.values().forEach(allIndexes::addAll);
                    
                    String htmlContent = response.substring(bodyOffset).toLowerCase();
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] HTML Content length for " + 
                        paramName + ": " + htmlContent.length());
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] First reflection position for " + 
                        paramName + ": " + (allIndexes.isEmpty() ? "none" : allIndexes.get(0)[0]));
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] HTML Content around reflection:\n" + 
                        htmlContent.substring(
                            Math.max(0, allIndexes.get(0)[0] - 50), 
                            Math.min(htmlContent.length(), allIndexes.get(0)[0] + 50)
                        ));
                    
                    ContextAnalyzer contextAnalyzer = new ContextAnalyzer(htmlContent, allIndexes, callbacks);
                    String contextResults = contextAnalyzer.getIssuesForAllParameters();
                    
                    callbacks.printOutput("[DEBUG-CONTEXT-DETAIL] Raw context results for " + 
                        paramName + ": " + contextResults);
                    
                    // Only include HTML context message if '<' was actually reflected
                    if (reflectedSpecialChars.contains("<")) {
                        symbols = contextResults;
                    } else {
                        // Remove HTML context message if '<' wasn't reflected
                        symbols = contextResults.replaceAll("HTML context \\(breaks out with <\\)", "").trim();
                    }
                    callbacks.printOutput("[DEBUG-PAYLOAD] Context analysis results: " + symbols);
                    callbacks.printOutput("[DEBUG-PAYLOAD] Reflected special chars: " + String.join(", ", reflectedSpecialChars));
                }
            } else if(bodyOffset != 1) {
                symbols = "";
                for (Map.Entry<String, ArrayList<int[]>> entry : reflectionMap.entrySet()) {
                    String character = entry.getKey();
                    ArrayList<int[]> indexes = entry.getValue();
                    
                    for (int[] indexPair : indexes) {
                        String extractedValue = response.substring(indexPair[0] + bodyOffset, indexPair[1] + bodyOffset);
                        callbacks.printOutput("[DEBUG-PAYLOAD] Processing reflected value: " + extractedValue);
                        callbacks.printOutput("[DEBUG-PAYLOAD] Reflected value bytes: " + Arrays.toString(extractedValue.getBytes()));
                        
                        reflectedPayloadValue = Aggressive.prepareReflectedPayload(extractedValue);
                        callbacks.printOutput("[DEBUG-PAYLOAD] Prepared payload value: " + reflectedPayloadValue);
                        callbacks.printOutput("[DEBUG-PAYLOAD] Prepared payload bytes: " + Arrays.toString(reflectedPayloadValue.getBytes()));
                        
                        if (reflectedPayloadValue.length() > 0) {
                            callbacks.printOutput("[DEBUG-PAYLOAD] Adding symbol: " + character);
                            symbols += character + " ";
                        }
                    }
                    if (!symbols.isEmpty()) {
                        symbols += " || ";
                    }
                }

                if (!symbols.equals("")) {
                    callbacks.printOutput("[DEBUG-PAYLOAD] Final symbols before encoding: " + symbols);
                    symbols = symbols.substring(0, symbols.length() - 4)
                        .replaceAll("<", "&lt;")
                        .replaceAll("'", "&#39;")
                        .replaceAll("\"", "&quot;")
                        .replaceAll("`", "&#96;")
                        .replaceAll("\\|\\|", "<b>|</b>");
                    callbacks.printOutput("[DEBUG-PAYLOAD] Final symbols after encoding: " + symbols);
                }
            }
        } catch (Exception e) {
            callbacks.printError("[DEBUG-PAYLOAD] Error: " + e.getMessage());
            e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            return "";
        }
        return symbols;
    }

    private String prepareRequest(Map parameter) {
        String payload = parameter.get(TYPE).equals(IParameter.PARAM_JSON) ? PAYLOAD_JSON : PAYLOAD;
        return prepareRequest(parameter, payload);
    }

    private String prepareRequest(Map parameter, String payload) {
        byte type = ((Integer)parameter.get(TYPE)).byteValue();
        IRequestInfo analyzedRequest = helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<String> headers = new ArrayList<>(analyzedRequest.getHeaders());
        byte[] body = Arrays.copyOfRange(baseRequestResponse.getRequest(), analyzedRequest.getBodyOffset(), baseRequestResponse.getRequest().length);
        
        callbacks.printOutput("[DEBUG-REQUEST] Preparing request with payload: " + payload);
        callbacks.printOutput("[DEBUG-REQUEST] Parameter type: " + getTypeString(type));
        
        // Handle header modifications (both request and response headers)
        if (type == Constants.REQUEST_HEADER || type == Constants.RESPONSE_HEADER) {
            String headerName = (String)parameter.get(NAME);
            String headerValue = PAYLOAD_GREP + payload + PAYLOAD_GREP;
            
            callbacks.printOutput("[DEBUG-REQUEST] Processing " + 
                (type == Constants.REQUEST_HEADER ? "request" : "response") + 
                " header: " + headerName);
            
            // Create a copy of headers to modify
            List<String> modifiedHeaders = new ArrayList<>(headers);
            boolean headerFound = false;
            
            // First check if this header exists in the original request
            for (int i = 0; i < modifiedHeaders.size(); i++) {
                String currentHeader = modifiedHeaders.get(i);
                if (currentHeader.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                    // Update existing header
                    modifiedHeaders.set(i, headerName + ": " + headerValue);
                    headerFound = true;
                    break;
                }
            }
            
            // If header wasn't found, add it as a new header
            if (!headerFound) {
                // Add new header after the first line (request/status line)
                modifiedHeaders.add(1, headerName + ": " + headerValue);
            }
            
            // Log all headers being sent
            callbacks.printOutput("[DEBUG-REQUEST] Sending headers:");
            for (String h : modifiedHeaders) {
                callbacks.printOutput("[DEBUG-REQUEST] " + h);
            }
            
            // Add cache busting headers and parameters
            checkReflection.addCacheBustingHeaders(modifiedHeaders);
            
            String firstLine = modifiedHeaders.get(0);
            if (firstLine.startsWith("GET")) {
                String url = firstLine.substring(4, firstLine.lastIndexOf(" HTTP"));
                url = checkReflection.addCacheBusterToUrl(url);
                modifiedHeaders.set(0, "GET " + url + " HTTP/1.1");
            } else if (body.length > 0) {
                String bodyStr = helpers.bytesToString(body);
                bodyStr = checkReflection.addCacheBusterToBody(bodyStr);
                body = bodyStr.getBytes();
            }
            
            // Build new request with modified headers
            byte[] newRequest = helpers.buildHttpMessage(modifiedHeaders, body);
            return helpers.bytesToString(newRequest);
        } 
        // Handle regular parameters
        else {
            String tmpRequest = helpers.bytesToString(baseRequestResponse.getRequest())
                .substring(0, (int)parameter.get("ValueStart")) + 
                PAYLOAD_GREP + payload + PAYLOAD_GREP + 
                helpers.bytesToString(baseRequestResponse.getRequest())
                .substring((int)parameter.get("ValueEnd"));
            
            // Update Content-Length if needed
            String contentLength = "";
            for (String header : headers) {
                if(header.toLowerCase().contains("content-length")) {
                    contentLength = header;
                    break;
                }
            }
            
            if (contentLength.equals("") || (int)parameter.get(VALUE_START) < analyzedRequest.getBodyOffset()) {
                return tmpRequest;
            }
            
            int paramLength = (int)parameter.get(VALUE_END) - (int)parameter.get(VALUE_START);
            int lengthDiff = (PAYLOAD_GREP + payload + PAYLOAD_GREP).length() - paramLength;
            String contentLengthString = contentLength.split(": ")[1].trim();
            int contentLengthInt = Integer.parseInt(contentLengthString) + lengthDiff;
            int contentLengthIntOffsetStart = tmpRequest.toLowerCase().indexOf("content-length");
            tmpRequest = tmpRequest.substring(0, contentLengthIntOffsetStart + 16) + 
                String.valueOf(contentLengthInt) +
                tmpRequest.substring(contentLengthIntOffsetStart + 16 + contentLengthString.length());
            
            return tmpRequest;
        }
    }
}
