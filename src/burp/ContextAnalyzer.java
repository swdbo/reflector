package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import static burp.Constants.*;

class ContextAnalyzer
{
    private class Tag {
        private int start;
        private int end;
        private String name;
        private ArrayList<Attribute> attrList;

        Tag(int start, int end, String name, ArrayList<Attribute> attrList) {
            this.start = start;
            this.end = end;
            this.name = name;
            this.attrList = attrList;
        }
    }

    private class Attribute {
        private int start;
        private int end;
        private char delimiter;

        Attribute(int start, int end, char delimiter) {
            this.start = start;
            this.end = end;
            this.delimiter = delimiter;
        }
    }

    private class Reflection {
        private int start;
        private String value;

        Reflection( int start, String value ) {
            this.start = start;
            this.value = value;
        }

        public int getStart() {
            return this.start;
        }
    }

    private ArrayList<Tag> tagList;
    private int[] startIndexes;
    private String body;
    private boolean vulnerableFlag;
    private ArrayList<Reflection> reflections;
    private IBurpExtenderCallbacks callbacks;

    ContextAnalyzer(String body, ArrayList<int[]> indexes, IBurpExtenderCallbacks callbacks) {
        this.tagList = new ArrayList<>();
        this.callbacks = callbacks;
        this.body = prepareBody(body, indexes);
        parseBody(this.body);
        deleteTagsBetweenScript();
        this.startIndexes = makeStartIndexes();
        this.vulnerableFlag = false;
    }

    private int[] makeStartIndexes() {
        int[] tmp = new int[this.tagList.size()];
        for (int i = 0; i < this.tagList.size(); i++) {
            tmp[i] = this.tagList.get(i).start;
        }
        return tmp;
    }

    public String getContext(int position) {
        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Analyzing position: " + position);
        // Add surrounding content for context
        int start = Math.max(0, position - 50);
        int end = Math.min(body.length(), position + 50);
        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Surrounding content:\n" + 
            body.substring(start, end));
            
        // Find the nearest opening tag before this position
        int tagStart = body.lastIndexOf("<", position);
        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Nearest tag start: " + tagStart);
        
        if (tagStart == -1) {
            callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] No tag found before position");
            return CONTEXT_OUT_OF_TAG;
        }

        int tagEnd = body.indexOf(">", tagStart);
        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Tag end: " + tagEnd);
        
        String tagContent = tagEnd != -1 ? body.substring(tagStart, tagEnd + 1) : "unclosed tag";
        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Tag content: " + tagContent);
        
        // Check if we're inside a tag
        if (tagEnd == -1 || position < tagEnd) {
            callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Position is inside tag");
            return CONTEXT_IN_TAG;
        }
        
        // Check if we're in text content (between tags)
        if (position > tagEnd) {
            // Look for the next opening tag
            int nextTagStart = body.indexOf("<", position);
            callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Next tag start: " + nextTagStart);
            
            if (nextTagStart == -1 || position < nextTagStart) {
                callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Position is in text content");
                return "Inside tag (no exploitable context found, but reflected chars: ";
            }
        }

        callbacks.printOutput("[DEBUG-CONTEXT-ANALYZER] Position is in default HTML context");
        return CONTEXT_OUT_OF_TAG;
    }

    public String getIssuesForAllParameters() {
        // Map to store characters found in each context
        Map<String, Set<String>> contextFindings = new HashMap<>();
        
        for (Reflection payload : this.reflections) {
            String reflectedPayloadValue = Aggressive.prepareReflectedPayload(payload.value);
            callbacks.printOutput("[DEBUG-CONTEXT] Processing reflection at position " + payload.getStart());
            callbacks.printOutput("[DEBUG-CONTEXT] Reflected value: " + payload.value);
            callbacks.printOutput("[DEBUG-CONTEXT] Prepared payload: " + reflectedPayloadValue);
            
            if (reflectedPayloadValue.length() > 0 && payload.getStart() >= 0) {
                String context = getContext(payload.getStart());
                callbacks.printOutput("[DEBUG-CONTEXT] Detected context: " + context);
                
                String contextChars = checksContextSecurity(reflectedPayloadValue, context);
                callbacks.printOutput("[DEBUG-CONTEXT] Context security check result: " + contextChars);
                
                if (contextChars != null) {
                    this.vulnerableFlag = true;
                    contextFindings.putIfAbsent(context, new HashSet<>());
                    contextFindings.get(context).add(contextChars);
                    reflectedPayloadValue = reflectedPayloadValue.replace(contextChars, "");
                }
                
                // If there are remaining chars, they go into the current context
                if (reflectedPayloadValue.length() > 0) {
                    contextFindings.putIfAbsent(context, new HashSet<>());
                    for (String chr : reflectedPayloadValue.split("")) {
                        contextFindings.get(context).add(chr);
                    }
                }
            }
        }
        
        // Build the output string
        StringBuilder result = new StringBuilder();
        
        // Process contexts in a specific order
        String[][] contextGroups = {
            // HTML context
            {CONTEXT_OUT_OF_TAG},
            // Tag context
            {CONTEXT_IN_TAG},
            // Attribute contexts
            {CONTEXT_IN_ATTRIBUTE_Q, CONTEXT_IN_ATTRIBUTE_DQ, CONTEXT_IN_ATTRIBUTE_BT},
            // Script contexts
            {CONTEXT_IN_SCRIPT_TAG, CONTEXT_IN_SCRIPT_TAG_STRING_Q, CONTEXT_IN_SCRIPT_TAG_STRING_DQ, CONTEXT_IN_SCRIPT_TAG_STRING_BT}
        };
        
        for (String[] group : contextGroups) {
            for (String context : group) {
                if (contextFindings.containsKey(context)) {
                    Set<String> chars = contextFindings.get(context);
                    // Only include context if relevant special chars were found
                    if (context.equals(CONTEXT_OUT_OF_TAG)) {
                        if (chars.contains("<")) {
                            result.append("HTML context (breaks out with <)");
                        }
                    } else if (context.equals(CONTEXT_IN_ATTRIBUTE_Q)) {
                        if (chars.contains("'")) {
                            result.append(context);
                        }
                    } else if (context.equals(CONTEXT_IN_ATTRIBUTE_DQ)) {
                        if (chars.contains("\"")) {
                            result.append(context);
                        }
                    } else if (context.equals(CONTEXT_IN_ATTRIBUTE_BT)) {
                        if (chars.contains("`")) {
                            result.append(context);
                        }
                    } else if (context.equals(CONTEXT_IN_SCRIPT_TAG_STRING_Q)) {
                        if (chars.contains("'")) {
                            result.append(context);
                        }
                    } else if (context.equals(CONTEXT_IN_SCRIPT_TAG_STRING_DQ)) {
                        if (chars.contains("\"")) {
                            result.append(context);
                        }
                    } else if (context.equals(CONTEXT_IN_SCRIPT_TAG_STRING_BT)) {
                        if (chars.contains("`")) {
                            result.append(context);
                        }
                    } else if (!chars.isEmpty()) {
                        // For other contexts or when chars are found but not in exploitable context
                        result.append(context);
                        if (context.equals(CONTEXT_OUT_OF_TAG) || context.equals(CONTEXT_IN_TAG)) {
                            result.append(" (no exploitable context found, but reflected chars: ")
                                  .append(String.join(" ", chars))
                                  .append(")");
                        } else {
                            result.append(" (found: ").append(String.join(" ", chars)).append(")");
                        }
                    }
                    result.append(" | ");
                }
            }
        }
        
        String finalResult = result.toString().trim();
        if (finalResult.endsWith("|")) {
            finalResult = finalResult.substring(0, finalResult.length() - 1).trim();
        }
        
        if (!finalResult.isEmpty()) {
            finalResult = finalResult
                .replaceAll("<", "&lt;")
                .replaceAll("'", "&#39;")
                .replaceAll("\"", "&quot;")
                .replaceAll("`", "&#96;");
            
            if (vulnerableFlag) {
                finalResult += CONTEXT_VULN_FLAG;
            }
        }
        
        return finalResult;
    }

    private String checkScript(int place, int start) {
        String tmpContext = this.body.substring( this.tagList.get(place).end, start).replaceAll("\\[\"']", "");
        int quote = 0;
        int doubleQuote = 0;
        int backtick = 0;
    
        for (char c : tmpContext.toCharArray()) {
            if (c == '\'' && doubleQuote == 0 && backtick == 0)
                quote = (quote == 0) ? 1 : 0;
            else if (c == '"' && quote == 0 && backtick == 0)
                doubleQuote = (doubleQuote == 0) ? 1 : 0;
            else if (c == '`' && quote == 0 && doubleQuote == 0)
                backtick = (backtick == 0) ? 1 : 0;
        }
    
        if (quote == 1)
            return CONTEXT_IN_SCRIPT_TAG_STRING_Q;
        if (doubleQuote == 1)
            return CONTEXT_IN_SCRIPT_TAG_STRING_DQ;
        if (backtick == 1)
            return CONTEXT_IN_SCRIPT_TAG_STRING_BT;
    
        return CONTEXT_IN_SCRIPT_TAG;
    }

    private String checkContextInTag(ArrayList<Attribute> attrList, int start) {
        char delimiter = '\0';
        for (Attribute attr : attrList) {
            if (attr.start <= start && attr.end >= start) {
                delimiter = attr.delimiter;
                break;
            }
        }
        switch (delimiter) {
            case '\'':
                return CONTEXT_IN_ATTRIBUTE_Q;
            case '"':
                return CONTEXT_IN_ATTRIBUTE_DQ;
            case '`':
                return CONTEXT_IN_ATTRIBUTE_BT;
            default:
                return CONTEXT_IN_TAG;
        }
    }

    private void deleteTagsBetweenScript() {
        ArrayList<Tag> tmpTags = new ArrayList<>();
        boolean script = false;
        for (Tag tag: this.tagList) {
            if ( tag.name.equals("script") && !script ) {
                script = true;
                tmpTags.add(tag);
                continue;
            } else if ( tag.name.equals("/script") && script ) {
                script = false;
                tmpTags.add(tag);
                continue;
            }
            if ( script ) {
                continue;
            }
            tmpTags.add(tag);
        }
        this.tagList = tmpTags;
    }

    private String prepareBody(String body, ArrayList<int[]> indexes) {
        String tmpBody = body;
        this.reflections = new ArrayList<>();
        int totalShift = 0;
        for (int[] indexPair : indexes) {
            if ( indexPair[0] < 0 ) {
                continue;
            }
            this.reflections.add(new Reflection(
                indexPair[0] - totalShift,
                tmpBody.substring(indexPair[0] - totalShift, indexPair[1] - totalShift)
            ));
            tmpBody = tmpBody.substring(0, indexPair[0] - totalShift) + tmpBody.substring(indexPair[1] - totalShift);
            totalShift += indexPair[1] - indexPair[0];
        }
        return tmpBody;
    }

    private void parseBody(String body) {
        String alphabet = "qwer/tyuiopasdfghjklzxcvbnm",
                name = "",
                tmpName = "";
        int attrStep = -1,
                startTag = -1,
                startAttr = -1,
                i = 0,
                bodyLength = body.length();
        char attrDelimiter = '\0';
        ArrayList<Attribute> tmpAttributes = null;

        while (i < bodyLength) {
            if (startTag == -1) {
                if (body.charAt(i) == '<' && (bodyLength > i + 1) && alphabet.contains(String.valueOf(body.charAt(i+1)))) {
                    startTag = i;
                    tmpAttributes = new ArrayList<Attribute>();
                }
                i += 1;
            } else if (startAttr == -1) {
                while ( ( name.equals("") ) && ( i < bodyLength ) ) {
                    if ( body.charAt(i) == ' ' || body.charAt(i) == '>' ) {
                        name = tmpName;
                        tmpName = "";
                    } else {
                        tmpName += body.charAt(i);
                        i += 1;
                    }
                }

                while ((startAttr == -1) && (i < bodyLength)) {
                    if (body.charAt(i) == '>') {
                        tagList.add(new Tag(startTag, i, name, tmpAttributes));
                        tmpAttributes = null;
                        name = "";
                        tmpName = "";
                        startTag = -1;
                        startAttr = -1;
                        attrStep = -1;
                        attrDelimiter = '\0';
                        i += 1;
                        break;
                    } else if (attrStep == -1) {
                        if (body.charAt(i) != ' ')
                            attrStep = 0;
                    } else if (attrStep == 0) {
                        if (body.charAt(i) == ' ')
                            attrStep = 1;
                        else if (body.charAt(i) == '=')
                            attrStep = 2;
                    } else if (attrStep == 1) {
                        if (body.charAt(i) == '=')
                            attrStep = 2;
                        else if (body.charAt(i) != ' ')
                            attrStep = -1;
                    } else if (attrStep == 2) {
                        if (body.charAt(i) == '"' || body.charAt(i) == '\'' || body.charAt(i) == '`') {
                            attrDelimiter = body.charAt(i);
                            startAttr = i;
                        } else if (body.charAt(i) != ' ') {
                            startAttr = i - 1;
                        }
                    }
                    i += 1;
                }
            } else {
                if ((body.charAt(i) == attrDelimiter && body.charAt(i - 1) != '\\' ) || (attrDelimiter == '\0' && " >/".contains(String.valueOf(body.charAt(i))))){
                    tmpAttributes.add(new Attribute(startAttr + 1, i, attrDelimiter));
                    startAttr = -1;
                    attrStep = -1;
                    attrDelimiter = '\0';
                } else {
                    i += 1;
                }
            }
        }
    }

    private String checksContextSecurity(String reflectedPayload, String context) {
        callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Checking security for context: " + context);
        callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Reflected payload: " + reflectedPayload);
        
        String result = null;
        // For contexts that expect specific characters, return only those characters if found
        switch (context) {
            case CONTEXT_OUT_OF_TAG:
                result = reflectedPayload.contains("<") ? "<" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] HTML context check: " + result);
                return result;
                
            case CONTEXT_IN_ATTRIBUTE_Q:
                result = reflectedPayload.contains("'") ? "'" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Single quote attribute check: " + result);
                return result;
                
            case CONTEXT_IN_ATTRIBUTE_DQ:
                result = reflectedPayload.contains("\"") ? "\"" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Double quote attribute check: " + result);
                return result;
                
            case CONTEXT_IN_ATTRIBUTE_BT:
                result = reflectedPayload.contains("`") ? "`" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Backtick attribute check: " + result);
                return result;
                
            case CONTEXT_IN_SCRIPT_TAG_STRING_Q:
                result = reflectedPayload.contains("'") ? "'" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Single quote script check: " + result);
                return result;
                
            case CONTEXT_IN_SCRIPT_TAG_STRING_DQ:
                result = reflectedPayload.contains("\"") ? "\"" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Double quote script check: " + result);
                return result;
                
            case CONTEXT_IN_SCRIPT_TAG_STRING_BT:
                result = reflectedPayload.contains("`") ? "`" : null;
                callbacks.printOutput("[DEBUG-CONTEXT-SECURITY] Backtick script check: " + result);
                return result;
                
            // For contexts that can accept any character
            case CONTEXT_IN_TAG:
            case CONTEXT_IN_SCRIPT_TAG:
                if (reflectedPayload.length() > 0) {
                    // Return each character that was found
                    StringBuilder foundChars = new StringBuilder();
                    for (char c : reflectedPayload.toCharArray()) {
                        foundChars.append(c);
                    }
                    return foundChars.toString();
                }
                return null;
                
            default:
                return null;
        }
    }
}
