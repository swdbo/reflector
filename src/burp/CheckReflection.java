package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Constants.*;

public class CheckReflection {

    public static final int QUOTE_BYTE = 34;
    private static final String CANARY_PREFIX = "bnr";
    private static final String CANARY_SUFFIX = "rbn";
    private final int bodyOffset;

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    IBurpExtenderCallbacks callbacks;
    private byte[] request;

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
            byte[] request = helpers.buildHttpRequest(helpers.analyzeRequest(iHttpRequestResponse).getUrl());
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
            
        if (bytesOfParamValue.length > 2) {
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
                
                // Update the parameter in the copied request
                canaryRequest = helpers.updateParameter(canaryRequest, 
                    helpers.buildParameter(parameter.getName(), canaryValue, parameter.getType()));
                
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
            
            // callbacks.printOutput(String.format("[HEADER CHECK] Testing %s header '%s' with value: %s",
            //     (isRequest ? "request" : "response"),
            //     headerName,
            //     headerValue));
            
            byte[] bytesOfHeaderValue = headerValue.getBytes();
            if (bytesOfHeaderValue.length > 2) {
                // For response headers, only check reflections in the response body
                List<int[]> originalMatches;
                if (!isRequest) {
                    // Get response body
                    byte[] response = iHttpRequestResponse.getResponse();
                    int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
                    byte[] bodyBytes = Arrays.copyOfRange(response, bodyOffset, response.length);
                    originalMatches = getMatches(bodyBytes, bytesOfHeaderValue);
                } else {
                    // For request headers, check entire response
                    originalMatches = getMatches(iHttpRequestResponse.getResponse(), bytesOfHeaderValue);
                }
                
                if (!originalMatches.isEmpty()) {
                    callbacks.printOutput(String.format("[BASIC REFLECTION] %s header '%s' appears to be reflected",
                        isRequest ? "Request" : "Response",
                        headerName));
                    
                    String canaryValue = generateCanaryValue();
                    callbacks.printOutput(String.format("[CANARY TESTING] Testing %s header '%s' with value: %s",
                        isRequest ? "request" : "response",
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
                    
                    byte[] canaryRequest = helpers.buildHttpMessage(modifiedHeaders, Arrays.copyOfRange(
                        iHttpRequestResponse.getRequest(),
                        helpers.analyzeRequest(iHttpRequestResponse.getRequest()).getBodyOffset(),
                        iHttpRequestResponse.getRequest().length));
                    
                    IHttpRequestResponse canaryResp = callbacks.makeHttpRequest(
                        iHttpRequestResponse.getHttpService(),
                        canaryRequest);
                    
                    List<int[]> canaryMatches;
                    if (!isRequest) {
                        byte[] canaryRespBody = Arrays.copyOfRange(
                            canaryResp.getResponse(),
                            helpers.analyzeResponse(canaryResp.getResponse()).getBodyOffset(),
                            canaryResp.getResponse().length);
                        canaryMatches = getMatches(canaryRespBody, canaryValue.getBytes());
                    } else {
                        canaryMatches = getMatches(canaryResp.getResponse(), canaryValue.getBytes());
                    }
                    
                    if (!canaryMatches.isEmpty()) {
                        callbacks.printOutput(String.format("[CANARY CONFIRMED] %s header '%s' reflection verified",
                            isRequest ? "Request" : "Response",
                            headerName));
                        
                        // Create parameter description map with proper TYPE field
                        Map<String, Object> headerDescription = new HashMap<>();
                        headerDescription.put(NAME, headerName);
                        headerDescription.put(VALUE, headerValue);
                        headerDescription.put(TYPE, Integer.valueOf(isRequest ? Constants.REQUEST_HEADER : Constants.RESPONSE_HEADER));
                        headerDescription.put(MATCHES, originalMatches);
                        headerDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(originalMatches));
                        
                        // Add header position information
                        byte[] fullMessage = isRequest ? request : iHttpRequestResponse.getResponse();
                        String fullMessageStr = helpers.bytesToString(fullMessage);
                        String headerLine = headerName + ": " + headerValue;
                        int headerStart = fullMessageStr.indexOf(headerLine);
                        if (headerStart != -1) {
                            int valueStart = headerStart + headerName.length() + 2; // +2 for ": "
                            headerDescription.put(VALUE_START, valueStart);
                            headerDescription.put(VALUE_END, valueStart + headerValue.length());
                        }
                        
                        reflectedParameters.add(headerDescription);
                    } else {
                        callbacks.printOutput("[CANARY FAILED] Header '" + headerName + "' reflection could not be verified");
                    }
                }
            }
        }
    }

    private boolean shouldSkipHeader(String headerName) {
        // List of headers that shouldn't be tested
        String[] skipHeaders = {
            "Content-Length",
            "Content-Type",
            "Date",
            "Expires",
            "Last-Modified"
        };
        
        return Arrays.asList(skipHeaders).contains(headerName);
    }

    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        String reflectIn = "";
        for(int[] matches : listOfMatches){
            if(matches[0] >= bodyOffset)
                if(reflectIn.equals(HEADERS))
                    return BOTH;
                else
                    reflectIn = BODY;
            else if(reflectIn.equals(BODY))
                    return BOTH;
                else
                    reflectIn = HEADERS;
        }
        return reflectIn;
    }

    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
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
    private List<String> reflectedSpecialChars;

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
        this.reflectedSpecialChars = new ArrayList<>();
    }

    public List<Map> scanReflectedParameters(){
        String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        String testRequest = "",
            symbols = "";
        
        for (Map param : reflectedParameters) {
            String paramName = (String)param.get(NAME);
            String paramType = getTypeString(((Integer)param.get(TYPE)).byteValue());
            callbacks.printOutput("[SPECIAL CHARS] Testing " + paramType + " '" + paramName + "' at " + url);
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
            symbols = checkResponse(testRequest);
            
            if (!symbols.equals("")) {
                callbacks.printOutput("[SPECIAL CHARS] " + paramType + " '" + paramName + "' is vulnerable to: " + symbols);
                param.put(VULNERABLE, symbols + "\n");
                param.put("reflectedSpecialChars", new ArrayList<>(reflectedSpecialChars));
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

    private String checkResponse(String testRequest) {
        String reflectedPayloadValue = "",
                symbols = "";
        int bodyOffset;
        try {
            Map<String, ArrayList<int[]>> reflectionMap = new HashMap<>();
            
            // Parse the parameter from the test request
            IRequestInfo requestInfo = helpers.analyzeRequest(testRequest.getBytes());
            List<IParameter> parameters = requestInfo.getParameters();
            if (parameters.isEmpty()) {
                return "";
            }
            IParameter currentParam = parameters.get(0);
            Map<String, Object> parameter = new HashMap<>();
            parameter.put(TYPE, Integer.valueOf(currentParam.getType()));
            parameter.put(VALUE_START, currentParam.getValueStart());
            parameter.put(VALUE_END, currentParam.getValueEnd());
            
            String chars = parameter.get(TYPE).equals(IParameter.PARAM_JSON) ? PAYLOAD_JSON : PAYLOAD;
            
            // Test each special character individually
            for (char c : chars.toCharArray()) {
                callbacks.printOutput("[DEBUG-PAYLOAD] Testing character: " + c);
                String singleCharRequest = prepareRequest(parameter, String.valueOf(c));
                
                IHttpRequestResponse responseObject = this.callbacks.makeHttpRequest(
                        this.baseRequestResponse.getHttpService(),
                        singleCharRequest.getBytes()
                );
                String response = helpers.bytesToString(responseObject.getResponse());
                callbacks.printOutput("[DEBUG-PAYLOAD] Got response of length: " + response.length());

                bodyOffset = helpers.analyzeResponse(responseObject.getResponse()).getBodyOffset();

                // Look for reflection of this specific character
                Pattern singleCharPattern = Pattern.compile(PAYLOAD_GREP + c + PAYLOAD_GREP);
                Matcher matcher = singleCharPattern.matcher(response);
                ArrayList<int[]> payloadIndexes = new ArrayList<>();
                
                while (matcher.find()) {
                    String matchedContent = response.substring(matcher.start(), matcher.end());
                    callbacks.printOutput("[DEBUG-PAYLOAD] Found match: " + matchedContent);
                    callbacks.printOutput("[DEBUG-PAYLOAD] Match bytes: " + Arrays.toString(matchedContent.getBytes()));
                    payloadIndexes.add(new int[]{matcher.start() - bodyOffset, matcher.end() - bodyOffset});
                    
                    // Track any special character that is found in a match
                    if (!reflectedSpecialChars.contains(String.valueOf(c))) {
                        reflectedSpecialChars.add(String.valueOf(c));
                        callbacks.printOutput("[DEBUG-PAYLOAD] Added special char to tracking: " + c);
                    }
                }
                
                if (!payloadIndexes.isEmpty()) {
                    reflectionMap.put(String.valueOf(c), payloadIndexes);
                }
            }

            if (reflectionMap.isEmpty()) {
                callbacks.printOutput("[DEBUG-PAYLOAD] No special characters reflected");
                return "";
            }

            // Get a combined response for context analysis
            String combinedPayload = String.join("", reflectionMap.keySet());
            String response = helpers.bytesToString(this.callbacks.makeHttpRequest(
                    this.baseRequestResponse.getHttpService(),
                    prepareRequest(parameter, combinedPayload).getBytes()
            ).getResponse());
            
            bodyOffset = helpers.analyzeResponse(response.getBytes()).getBodyOffset();
            
            if (settings.getCheckContext() && bodyOffset != response.length()) {
                // Combine all payload indexes for context analysis
                ArrayList<int[]> allIndexes = new ArrayList<>();
                reflectionMap.values().forEach(allIndexes::addAll);
                
                ContextAnalyzer contextAnalyzer = new ContextAnalyzer(response.substring(bodyOffset).toLowerCase(), allIndexes);
                symbols = contextAnalyzer.getIssuesForAllParameters();
                callbacks.printOutput("[DEBUG-PAYLOAD] Context analysis results: " + symbols);
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
        String tmpRequest = helpers.bytesToString(baseRequestResponse.getRequest()).substring(0, (int)parameter.get("ValueStart")) + PAYLOAD_GREP
                + payload + PAYLOAD_GREP + helpers.bytesToString(baseRequestResponse.getRequest()).substring((int)parameter.get("ValueEnd"));
        String contentLength = "";
        for (String header : helpers.analyzeRequest(baseRequestResponse).getHeaders())
        {
            if(header.toLowerCase().contains("content-length")) {
                contentLength = header;
                break;
            }
        }
        if (contentLength.equals("") || (int)parameter.get(VALUE_START) < helpers.analyzeRequest(baseRequestResponse).getBodyOffset()) {
            return  tmpRequest;
        }
        int paramLength = (int)parameter.get(VALUE_END) - (int)parameter.get(VALUE_START);
        int lengthDiff = (PAYLOAD_GREP + payload + PAYLOAD_GREP).length() - paramLength;
        String contentLengthString = contentLength.split(": ")[1].trim();
        int contentLengthInt = Integer.parseInt(contentLengthString) + lengthDiff;
        int contentLengthIntOffsetStart = tmpRequest.toLowerCase().indexOf("content-length");
        tmpRequest = tmpRequest.substring(0, contentLengthIntOffsetStart + 16) + String.valueOf(contentLengthInt) +
                tmpRequest.substring(contentLengthIntOffsetStart + 16 + contentLengthString.length());
        return tmpRequest;
    }
}
