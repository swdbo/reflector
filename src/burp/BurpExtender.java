package burp;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.UUID;

import static burp.Constants.*;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab, IContextMenuFactory
{
    public static final String PLUGIN_NAME = "Reflector";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final String DESCRIPTION_DETAILS = "Reflected parameters in ";
    private static final String XSS_POSSIBLE = "XSS (possible)";
    private static final String XSS_VULNERABLE= "XSS (vulnerable)";
    public static final String ALLOWED_CONTENT_TYPE = "Allowed Content-Type";
    public static final String DELETE = "Delete";
    public static final String ADD = "Add";
    private JPanel panel;
    private final String OPTIONS_NAME = "Scanner options";
    private final String AGGRESSIVE_MODE = "Aggressive mode";
    private final String SCOPE_ONLY = "Scope only";
    private final String CHECK_CONTEXT = "Check context";
    private JButton addButton;
    private JButton deleteButton;
    private JButton refreshButton;
    private JLabel refreshStatus;
    private JList<String> headerList;
    private HeaderListModel headerListModel;
    private JButton addHeaderButton;
    private JButton removeHeaderButton;
    private JTextField headerTextField;
    private JTextField contetTtypeTextField;
    private JTable contentTypeTable;
    private TableModel contentTypeModel;
    private JTable parameterTable;
    private ParameterTableModel parameterModel;
    private JCheckBox scopeOnly;
    private JCheckBox aggressiveMode;
    private JCheckBox checkContext;
    private Settings settings;
    private String issueName = XSS_POSSIBLE;

    private CheckReflection checkReflection;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(PLUGIN_NAME);

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        // register ourselves as a context menu factory
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                settings = new Settings(callbacks);
                panel = new JPanel();
                panel.setLayout(null);
                panel.setPreferredSize(new Dimension(800, 650)); // Ensure panel is large enough for both tables

                final JLabel label1 = new JLabel(OPTIONS_NAME);
                label1.setFont(new Font(label1.getFont().getName(), Font.BOLD, 16));
                label1.setBounds(58, 20, 130, 20);
                panel.add(label1);

                // Content Type Table
                contentTypeModel = new BurpTableModel(settings);
                contentTypeTable = new JTable(contentTypeModel);
                TableColumnModel columnModel = contentTypeTable.getColumnModel();
                columnModel.getColumn(0).setPreferredWidth(65);
                columnModel.getColumn(1).setPreferredWidth(330);

                JScrollPane contentTypeSp = new JScrollPane(contentTypeTable);
                contentTypeTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                contentTypeSp.setBounds(58, 200, 400, 150);
                contentTypeSp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                
                // Parameter History Table
                parameterModel = new ParameterTableModel();
                parameterTable = new JTable(parameterModel);
                
                // Enable sorting
                parameterTable.setAutoCreateRowSorter(true);
                // Set default sort on name column
                parameterTable.getRowSorter().toggleSortOrder(0);
                
                // Set column widths proportionally
                parameterTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
                TableColumnModel paramColumnModel = parameterTable.getColumnModel();
                int totalWidth = panel.getPreferredSize().width - 116; // Account for margins
                paramColumnModel.getColumn(0).setPreferredWidth((int)(totalWidth * 0.2)); // Name
                paramColumnModel.getColumn(1).setPreferredWidth((int)(totalWidth * 0.15)); // Type
                paramColumnModel.getColumn(2).setPreferredWidth((int)(totalWidth * 0.1));  // Requests
                paramColumnModel.getColumn(3).setPreferredWidth((int)(totalWidth * 0.1));  // Unique URLs
                paramColumnModel.getColumn(4).setPreferredWidth((int)(totalWidth * 0.1));  // Unique Values
                paramColumnModel.getColumn(5).setPreferredWidth((int)(totalWidth * 0.15)); // Reflected times
                paramColumnModel.getColumn(6).setPreferredWidth((int)(totalWidth * 0.2));  // Example Value
                
                JScrollPane parameterSp = new JScrollPane(parameterTable);
                parameterSp.setBounds(58, 400, totalWidth, 200);
                parameterSp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                parameterSp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

                // Add section labels
                JLabel contentTypeLabel = new JLabel("Content Type Settings");
                contentTypeLabel.setFont(new Font(contentTypeLabel.getFont().getName(), Font.BOLD, 14));
                contentTypeLabel.setBounds(58, 180, 200, 20);
                
                // Parameter History section
                JPanel parameterHeaderPanel = new JPanel();
                parameterHeaderPanel.setLayout(new BoxLayout(parameterHeaderPanel, BoxLayout.X_AXIS));
                parameterHeaderPanel.setBounds(58, 380, 700, 20);
                
                JLabel parameterLabel = new JLabel("Parameter History");
                parameterLabel.setFont(new Font(parameterLabel.getFont().getName(), Font.BOLD, 14));
                parameterHeaderPanel.add(parameterLabel);
                parameterHeaderPanel.add(Box.createHorizontalGlue());
                
                refreshButton = new JButton("Refresh History");
                refreshStatus = new JLabel("");
                refreshStatus.setForeground(Color.GRAY);
                parameterHeaderPanel.add(refreshStatus);
                parameterHeaderPanel.add(Box.createRigidArea(new Dimension(10, 0)));
                parameterHeaderPanel.add(refreshButton);

                deleteButton = new JButton(DELETE);
                deleteButton.setBounds(58, 355, 130, 30);
                
                // Header Names List section
                JLabel headerListLabel = new JLabel("Interesting Headers");
                headerListLabel.setFont(new Font(headerListLabel.getFont().getName(), Font.BOLD, 14));
                headerListLabel.setBounds(500, 180, 200, 20);
                
                headerListModel = new HeaderListModel();
                headerList = new JList<>(headerListModel);
                JScrollPane headerListSp = new JScrollPane(headerList);
                headerListSp.setBounds(500, 200, 250, 150);
                
                headerTextField = new JTextField();
                headerTextField.setBounds(500, 355, 150, 25);
                
                addHeaderButton = new JButton("Add");
                addHeaderButton.setBounds(660, 355, 70, 25);
                
                removeHeaderButton = new JButton("Remove");
                removeHeaderButton.setBounds(735, 355, 80, 25);
                
                panel.add(headerListLabel);
                panel.add(headerListSp);
                panel.add(headerTextField);
                panel.add(addHeaderButton);
                panel.add(removeHeaderButton);
                
                panel.add(contentTypeLabel);
                panel.add(parameterHeaderPanel);
                panel.add(deleteButton);
                panel.add(contentTypeSp);
                panel.add(parameterSp);

                contetTtypeTextField = new JTextField();
                contetTtypeTextField.setBounds(200, 143, 160, 29);
                panel.add(contetTtypeTextField);
                contetTtypeTextField.setColumns(10);

                JLabel addLabel = new JLabel(ALLOWED_CONTENT_TYPE);
                addLabel.setBounds(58, 150, 140, 16);
                addLabel.setFont(new Font(label1.getFont().getName(), Font.PLAIN ,14));
                panel.add(addLabel);
                addButton = new JButton(ADD);
                addButton.setBounds(370, 143, 84, 30);
                panel.add(addButton);
                BurpExtender.OptionPanel optionPanel1 = placeOption(SCOPE_ONLY);
                JPanel option1 = optionPanel1.getPanel();
                scopeOnly = optionPanel1.getCheckBox();
                scopeOnly.setSelected(settings.getScopeOnly());
                option1.setBounds(58, 43, 130, 20);
                panel.add(option1);
                BurpExtender.OptionPanel optionPanel2 = placeOption(AGGRESSIVE_MODE);
                JPanel option2 = optionPanel2.getPanel();
                aggressiveMode = optionPanel2.getCheckBox();
                aggressiveMode.setSelected(settings.getAggressiveMode());
                option2.setBounds(58, 63, 135, 20);
                panel.add(option2);
                BurpExtender.OptionPanel optionPanel3 = placeOption(CHECK_CONTEXT);
                JPanel option3 = optionPanel3.getPanel();
                checkContext = optionPanel3.getCheckBox();
                checkContext.setSelected(settings.getCheckContext());
                option3.setBounds(58, 83, 130, 20);
                panel.add(option3);


                initListener();


                callbacks.customizeUiComponent(panel);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    //listener  initializations
    private void initListener(){
        // Header list buttons
        addHeaderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String header = headerTextField.getText().trim();
                if (!header.isEmpty() && !headerListModel.contains(header)) {
                    headerListModel.addElement(header);
                    headerTextField.setText("");
                }
            }
        });
        
        removeHeaderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = headerList.getSelectedIndex();
                if (index != -1) {
                    headerListModel.remove(index);
                }
            }
        });
        
        // Add keyboard listener to header text field
        headerTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    addHeaderButton.doClick();
                }
            }
        });

        // Refresh button
        refreshButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshButton.setEnabled(false);
                refreshStatus.setText("Refreshing...");
                
                // Run in background thread to avoid freezing UI
                new Thread(() -> {
                    try {
                        parameterModel.clear();
                        IHttpRequestResponse[] proxyHistory = callbacks.getProxyHistory();
                        int total = proxyHistory.length;
                        int processed = 0;
                        
                        for (IHttpRequestResponse message : proxyHistory) {
                            processed++;
                            if (processed % 100 == 0) { // Update status every 100 requests
                                final int current = processed;
                                SwingUtilities.invokeLater(() -> 
                                    refreshStatus.setText(String.format("Processed %d/%d requests...", current, total)));
                            }
                            
                            IRequestInfo requestInfo = helpers.analyzeRequest(message);
                            if (settings.getScopeOnly() && !callbacks.isInScope(requestInfo.getUrl())) {
                                continue;
                            }

                            String url = requestInfo.getUrl().toString();
                            byte[] response = message.getResponse();
                            String responseStr = helpers.bytesToString(response);
                            
                            // Get parameters from URL and body
                            for (IParameter param : requestInfo.getParameters()) {
                                String paramType = getParameterTypeDescription((int)param.getType());
                                String paramValue = param.getValue();
                                
                                // Simple reflection check: param=value in response
                                List<int[]> matches = new ArrayList<>();
                                String searchStr = param.getName() + "=" + paramValue;
                                int index = responseStr.indexOf(searchStr);
                                while (index != -1) {
                                    matches.add(new int[]{index, index + searchStr.length()});
                                    index = responseStr.indexOf(searchStr, index + 1);
                                }
                                
                                parameterModel.updateParameter(
                                    param.getName(),
                                    paramType,
                                    paramValue,
                                    url,
                                    matches
                                );
                            }
                            
                            // Get headers
                            List<String> headers = requestInfo.getHeaders();
                            for (int i = 1; i < headers.size(); i++) { // Skip first line (request line)
                                String header = headers.get(i);
                                int colonIndex = header.indexOf(':');
                                if (colonIndex > 0) {
                                    String name = header.substring(0, colonIndex).trim();
                                    String value = header.substring(colonIndex + 1).trim();
                                    
                                    // Simple reflection check for headers
                                    List<int[]> matches = new ArrayList<>();
                                    String searchStr = name + ": " + value;
                                    int index = responseStr.indexOf(searchStr);
                                    while (index != -1) {
                                        matches.add(new int[]{index, index + searchStr.length()});
                                        index = responseStr.indexOf(searchStr, index + 1);
                                    }
                                    
                                    parameterModel.updateParameter(
                                        name,
                                        "Header",
                                        value,
                                        url,
                                        matches
                                    );
                                }
                            }
                        }
                        
                        // Update UI when done
                        SwingUtilities.invokeLater(() -> {
                            refreshButton.setEnabled(true);
                            refreshStatus.setText(String.format("Found %d unique parameters", parameterModel.getRowCount()));
                        });
                    } catch (Exception ex) {
                        // Handle any errors
                        SwingUtilities.invokeLater(() -> {
                            refreshButton.setEnabled(true);
                            refreshStatus.setText("Error during refresh");
                            callbacks.printError("Error during parameter history refresh: " + ex.getMessage());
                        });
                    }
                }, "Parameter-History-Refresh").start();
            }
        });


        //add button
        addButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                String type = contetTtypeTextField.getText();
                Object[] rowData = {Boolean.TRUE, type};
                ((BurpTableModel)contentTypeModel).addRow(rowData);
            }
        });

        //delete button
        deleteButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                int i = contentTypeTable.getSelectedRow();
                if(i >= 0){
                    ((BurpTableModel)contentTypeModel).removeRow(i);
                }
            }
        });

        //content type table checkboxes
        contentTypeTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int column = contentTypeTable.getSelectedColumn();
                int row = contentTypeTable.getSelectedRow();
                if(column == 0 && row >=0){
                    Boolean value = (Boolean)contentTypeModel.getValueAt(row,column);
                    value = !value;
                    contentTypeModel.setValueAt(value, row, column);
                }
            }
        });

        //checkbox option
        scopeOnly.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                settings.setScopeOnly(scopeOnly.isSelected());
            }
        });

        //checkbox option
        aggressiveMode.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setAggressiveMode(aggressiveMode.isSelected());
            }
        });

        //checkbox option
        checkContext.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setCheckContext(checkContext.isSelected());
            }
        });

    }

    private OptionPanel placeOption(String optionName)
    {
        JPanel panelOption = new JPanel();
        BoxLayout boxlayout = new BoxLayout(panelOption, BoxLayout.X_AXIS);
        panelOption.setLayout(boxlayout);
        JCheckBox checkBox1 = new JCheckBox();
        checkBox1.setText("");
        panelOption.add(checkBox1);
        panelOption.add(Box.createRigidArea(new Dimension(5, 5)));
        final JLabel label1 = new JLabel();
        label1.setText(optionName);
        label1.setFont(new Font(label1.getFont().getName(), Font.PLAIN, 14));
        panelOption.add(label1);
        panelOption.setAlignmentX(Component.LEFT_ALIGNMENT);
        return new OptionPanel(panelOption, checkBox1);
    }

    @Override
    public String getTabCaption()
    {
        return PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return panel;
    }



    final class OptionPanel {
        private final JPanel panel;
        private final JCheckBox checkBox;

        public OptionPanel(JPanel panel, JCheckBox checkbox) {
            this.panel = panel;
            this.checkBox = checkbox;
        }

        public JPanel getPanel() {
            return panel;
        }

        public JCheckBox getCheckBox() {
            return checkBox;
        }
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
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

    //
    // implement IScannerCheck
    //


    private String buildIssueForReflection(Map param, IHttpRequestResponse baseRequestResponse) {
        int type;
        Object typeObj = param.get(TYPE);
        
        if (typeObj instanceof Byte) {
            type = ((Byte) typeObj).intValue();
        } else if (typeObj instanceof Integer) {
            type = (Integer) typeObj;
        } else {
            type = -1; // default case
        }
        
        String parameterType = getParameterTypeDescription(type);
        String paramName = (String)param.get(NAME);
        List<int[]> matches = (List<int[]>)param.get(MATCHES);
        String vulnerableChars = param.containsKey(VULNERABLE) ? (String)param.get(VULNERABLE) : "";
        List<String> reflectedSpecialChars = param.containsKey("reflectedSpecialChars") ? 
            (List<String>)param.get("reflectedSpecialChars") : new ArrayList<>();
        
        StringBuilder result = new StringBuilder("<li>");
        
        // Get the URL from the base request
        String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        
        // Build the output line
        result.append(String.format("%s '%s' - [%s] - %s - %s=%s - reflected %d times",
            parameterType,
            paramName,
            String.join("", (reflectedSpecialChars.isEmpty() ? "" : "[ " + String.join(" ", reflectedSpecialChars) + " ]")),  // Sort the characters for consistent output
            url,
            paramName,
            param.get(VALUE),
            matches.size()));
        
        if (!vulnerableChars.isEmpty()) {
            result.append(" and allow the following characters:<br>");
            result.append(vulnerableChars.replace(" | ", "<br>"));
            
            // Context checking logic
            if (settings.getCheckContext() && !vulnerableChars.contains(CONTEXT_VULN_FLAG)) {
                return result.append("</li>").toString();
            }
            issueName = XSS_VULNERABLE;
        }
        
        return result.append("</li>").toString();
    }

    private String getParameterTypeDescription(int type) {
        if (type == IParameter.PARAM_COOKIE) {
            return "Cookie";
        } else if (type == IParameter.PARAM_URL) {
            return "URL Parameter";
        } else if (type == IParameter.PARAM_BODY) {
            return "Body Parameter";
        } else if (type == Constants.REQUEST_HEADER) {
            return "Request Header";
        } else if (type == Constants.RESPONSE_HEADER) {
            return "Response Header";
        }
        return "Parameter";
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) throws RuntimeException {
        return doPassiveScan(baseRequestResponse, false);
    }

    private List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse, boolean includeCustomHeaders) throws RuntimeException {
        // Check if URL is in scope
        if (settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
            return null;
        }

        // Check content type
        String contentType = "";
        for (String header: helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders()) {
            if (header.toLowerCase().contains("content-type: ")) {
                contentType = header.toLowerCase().split(": ", 2)[1];
                break;
            }
        }
        if (settings.getEnabledContentTypes() == null)
            return null;
        boolean isContentTypeAllowed = false;
        for (String allowedContentType: settings.getEnabledContentTypes()) {
            if (contentType.contains(allowedContentType)) {
                contentType = allowedContentType;
                isContentTypeAllowed = true;
                break;
            }
        }
        if (!isContentTypeAllowed) {
            callbacks.printOutput("[!] Skipping scan - content type not allowed: " + contentType);
            return null;
        }

        // Reset issue name at start of scan
        issueName = XSS_POSSIBLE;

        // Get request info
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        String url = requestInfo.getUrl().toString();
        byte[] request = baseRequestResponse.getRequest();
        List<String> headers = requestInfo.getHeaders();
        
        // Add custom headers to the request if needed
        IHttpRequestResponse requestToTest = baseRequestResponse;
        if (includeCustomHeaders && headerListModel.getSize() > 0) {
            callbacks.printOutput("\n[+] Adding custom headers to request for: " + url);
            callbacks.printOutput("[+] Number of custom headers to test: " + headerListModel.getSize());
            
            // Add all custom headers in a single request
            List<String> newHeaders = new ArrayList<>(headers);
            
            // Generate unique values for each header
            for (int i = 0; i < headerListModel.getSize(); i++) {
                String headerName = headerListModel.getElementAt(i);
                String headerValue = "BURP-TEST-" + headerName + "-VALUE-" + UUID.randomUUID().toString().substring(0, 8);
                newHeaders.add(headerName + ": " + headerValue);
            }
            
            // Build and send request with all headers
            byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
            byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);
            requestToTest = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        }
        
        // Do reflection checks for both regular parameters and custom headers
        this.checkReflection = new CheckReflection(settings, helpers, requestToTest, callbacks);
        List<Map> reflections = this.checkReflection.checkResponse();
        if (reflections.isEmpty()) {
            return null;
        }

        // Build the issue
        String reflectedInBody = "";
        String reflectedInHeader = "";
        String reflectedInAll = "";
        List<int[]> matches = new ArrayList<>();
        List<Pair> pairs = new ArrayList<>();
        
        for(Map param: reflections) {
            // Update parameter history table
            String paramName = (String)param.get(NAME);
            String paramType = getParameterTypeDescription(param.get(TYPE) instanceof Byte ? 
                ((Byte)param.get(TYPE)).intValue() : 
                (Integer)param.get(TYPE));
            String paramValue = (String)param.get(VALUE);
            List<int[]> paramMatches = (List<int[]>)param.get(MATCHES);
            parameterModel.updateParameter(paramName, paramType, paramValue, url, paramMatches);

            // Build reflection summary
            if(param.get(REFLECTED_IN).equals(BODY)){
                reflectedInBody += buildIssueForReflection(param, baseRequestResponse);
            }
            if(param.get(REFLECTED_IN).equals(HEADERS)){
                reflectedInHeader += buildIssueForReflection(param, baseRequestResponse);
            }
            if(param.get(REFLECTED_IN).equals(BOTH)){
                reflectedInAll += buildIssueForReflection(param, baseRequestResponse);
            }
            
            for (Object pair : (ArrayList)param.get(MATCHES)) {
                pairs.add(new Pair((int[]) pair));
            }
        }

        // Build reflection summary
        String START = ":<br><ul>";
        String END = "</ul>";
        String reflectedSummary = "";
        if(!reflectedInHeader.equals(""))
            reflectedSummary += DESCRIPTION_DETAILS + HEADERS + START + reflectedInHeader + END;
        if(!reflectedInBody.equals(""))
            reflectedSummary += DESCRIPTION_DETAILS + BODY + START + reflectedInBody + END;
        if(!reflectedInAll.equals(""))
            reflectedSummary += DESCRIPTION_DETAILS + BOTH + START + reflectedInAll + END;

        // Sort and merge matches
        Collections.sort(pairs, (o1, o2) -> {
            if (o1.getStart() == o2.getStart()) return 0;
            return o1.getStart() < o2.getStart() ? -1 : 1;
        });
        
        int[] tmpPair = null;
        for (Pair pair : pairs) {
            if (tmpPair == null) {
                tmpPair = pair.getPair();
            } else if (tmpPair[1] > pair.getPair()[0]) {
                tmpPair[1] = pair.getPair()[1];
            } else {
                matches.add(tmpPair);
                tmpPair = pair.getPair();
            }
        }
        if (tmpPair != null) {
            matches.add(tmpPair);
        }

        List<IScanIssue> issues = new ArrayList<>();
        issues.add(new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                issueName,
                reflectedSummary,
                getSeverity(issueName)));
        return issues;
    }

    private enum ScanType {
        REGULAR,    // Normal scan with existing parameters
        CUSTOM      // Only scan custom headers from our list
    }

    private void runScan(IContextMenuInvocation invocation, ScanType scanType) {
        new Thread(() -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages != null && messages.length > 0) {
                for (IHttpRequestResponse message : messages) {
                    callbacks.printOutput("[+] Starting reflection test for: " + 
                        helpers.analyzeRequest(message).getUrl().toString());
                    
                    // Run scan based on type
                    List<IScanIssue> issues = doPassiveScan(message, scanType == ScanType.CUSTOM);
                    
                    if (issues != null) {
                        for (IScanIssue issue : issues) {
                            callbacks.addScanIssue(issue);
                        }
                    }
                }
            }
        }, "Reflection-Scanner-Thread").start();
    }

    private String getSeverity(String issueName) {
        return XSS_VULNERABLE.equals(issueName) ? "High" : "Medium";
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
        {
            return -1;
        } else {
            return 0;
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        // Regular scan
        JMenuItem regularItem = new JMenuItem("Test this URL for reflections - existing");
        regularItem.addActionListener(e -> runScan(invocation, ScanType.REGULAR));
        menuItems.add(regularItem);
        
        // Custom headers only scan
        JMenuItem customItem = new JMenuItem("Test this URL for reflections - custom");
        customItem.addActionListener(e -> runScan(invocation, ScanType.CUSTOM));
        menuItems.add(customItem);
        
        return menuItems;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}
