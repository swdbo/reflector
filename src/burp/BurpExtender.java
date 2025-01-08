package burp;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.util.*;
import java.util.List;

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
    private JTextField contetTtypeTextField;
    private JTable table;
    private TableModel model;
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

                final JLabel label1 = new JLabel(OPTIONS_NAME);
                label1.setFont(new Font(label1.getFont().getName(), Font.BOLD, 16));
                label1.setBounds(58, 20, 130, 20);
                panel.add(label1);

                model = new BurpTableModel(settings);

                table=new JTable(model);
                TableColumnModel columnModel = table.getColumnModel();
                columnModel.getColumn(0).setPreferredWidth(65);
                columnModel.getColumn(1).setPreferredWidth(330);

                JScrollPane sp = new JScrollPane(table);
                table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                sp.setBounds(58, 200, 400, 250);
                sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                sp.setPreferredSize(new Dimension(400, 250));

                deleteButton = new JButton(DELETE);
                deleteButton.setBounds(58, 470, 130, 30  );
                panel.add(deleteButton);
                panel.add(sp);

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

        //add button
        addButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                String type = contetTtypeTextField.getText();
                Object[] rowData = {Boolean.TRUE, type};
                ((BurpTableModel)model).addRow(rowData);
            }
        });

        //delete button
        deleteButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                int i = table.getSelectedRow();
                if(i >= 0){
                    ((BurpTableModel)model).removeRow(i);
                }
            }
        });

        //table checkboxes
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int column = table.getSelectedColumn();
                int row = table.getSelectedRow();
                if(column == 0 && row >=0){
                    Boolean value = (Boolean)model.getValueAt(row,column);
                    value = !value;
                    model.setValueAt(value, row, column);
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
        
        StringBuilder result = new StringBuilder("<li>");
        
        // Extract all special characters from the findings
        Set<String> allChars = new HashSet<>();
        if (!vulnerableChars.isEmpty()) {
            for (String context : vulnerableChars.split(" \\| ")) {
                if (context.contains("(found: ")) {
                    String chars = context.substring(context.indexOf("found: ") + 7, context.indexOf(")"));
                    for (String c : chars.split(" ")) {
                        allChars.add(c);
                    }
                } else if (context.contains("breaks out with ")) {
                    String c = context.substring(context.indexOf("breaks out with ") + 14).replaceAll("[)]", "");
                    allChars.add(c);
                }
            }
        }
        
        // Get the URL from the base request
        String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        
        // Build the output line
        result.append(String.format("%s '%s' - [%s] - %s - %s=%s - reflected %d times",
            parameterType,
            paramName,
            String.join("", new TreeSet<>(allChars)),  // Sort the characters for consistent output
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

    // ## previous version
    // private String buildIssueForReflection( Map param)
    // {
    //     String reflectedIn = "";
    //     reflectedIn+="<li>";
    //     reflectedIn+=param.get(NAME);
    //     reflectedIn+=" - reflected "+ String.valueOf(((List)param.get(MATCHES)).size())+" times ";
    //     if (param.containsKey(VULNERABLE))
    //     {
    //         reflectedIn += "and allow the following characters: "+ String.valueOf(param.get(VULNERABLE));
    //         if (settings.getCheckContext() && !String.valueOf(param.get(VULNERABLE)).contains(CONTEXT_VULN_FLAG))
    //             return reflectedIn+ "</li>" ;
    //         issueName = XSS_VULNERABLE;
    //     }
    //     return reflectedIn+ "</li>" ;
    // }
    

    private String getParameterTypeDescription(Integer type) {
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
        if ( this.settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl()) )
            return null;
        // check content type
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
        issueName = XSS_POSSIBLE;
        // start analyze request
        if ( isContentTypeAllowed )
        {
            //Initialize check reflections
            this.checkReflection = new CheckReflection(settings, helpers, baseRequestResponse, callbacks);
            List<Map> reflections = this.checkReflection.checkResponse();
            if (!reflections.isEmpty())
            {
                // report the issue
                String reflectedInBody = "";
                String reflectedInHeader = "";
                String reflectedInAll = "";
                List<int[]> matches = new ArrayList<>();
                List<Pair> pairs = new ArrayList<>();
                for(Map param: reflections) {

                    if(param.get(REFLECTED_IN).equals(BODY)){
                        reflectedInBody+=buildIssueForReflection(param, baseRequestResponse);
                    }

                    if(param.get(REFLECTED_IN).equals(HEADERS)){
                        reflectedInHeader+=buildIssueForReflection(param, baseRequestResponse);
                    }


                    if(param.get(REFLECTED_IN).equals(BOTH)){
                        reflectedInAll+=buildIssueForReflection(param, baseRequestResponse);
                    }


                    for (Object pair : (ArrayList)param.get(MATCHES)) {
                        pairs.add(new Pair((int[]) pair));
                    }
                }
                String START = ":<br><ul>";
                String END = "</ul>";
                String reflectedSummary = "";
                if(!reflectedInHeader.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + HEADERS+START+reflectedInHeader+END;
                if(!reflectedInBody.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + BODY + START + reflectedInBody+END;
                if(!reflectedInAll.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS+BOTH+START+reflectedInAll+END;
                Collections.sort(pairs, new Comparator<Pair>() {
                    @Override
                    public int compare(Pair o1, Pair o2) {
                        if (o1.getStart() == o2.getStart())
                            return 0;
                        return o1.getStart() < o2.getStart() ? -1 : 1;
                    }
                });
                int[] tmpPair = null;
                for (Pair pair : pairs)
                {
                    if (tmpPair == null)
                        tmpPair = pair.getPair();
                    else if (tmpPair[1] > pair.getPair()[0])
                        tmpPair[1] = pair.getPair()[1];
                    else {
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
            } else return null;
        }
        else return null;
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
        
        JMenuItem menuItem = new JMenuItem("Test this URL for reflections");
        menuItem.addActionListener(e -> {
            // Run in a separate thread
            new Thread(() -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    for (IHttpRequestResponse message : messages) {
                        callbacks.printOutput("[+] Starting reflection test for: " + 
                            helpers.analyzeRequest(message).getUrl().toString());
                        // Run the same scan as the passive scanner
                        List<IScanIssue> issues = doPassiveScan(message);
                        if (issues != null) {
                            for (IScanIssue issue : issues) {
                                callbacks.addScanIssue(issue);
                            }
                        }
                    }
                }
            }, "Reflection-Scanner-Thread").start();
        });
        
        menuItems.add(menuItem);
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
