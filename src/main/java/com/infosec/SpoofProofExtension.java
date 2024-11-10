package com.infosec;

import burp.*;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * SpoofProofExtension is a Burp Suite extension that checks DMARC, SPF, and DKIM records for a given domain.
 * It provides recommendations and a final verdict on the domain's email security configuration.
 */
public class SpoofProofExtension implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stderr; // For error logging
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private JTable table;
    private JTextField domainInput;

    // Default DNS servers (Google's)
    private String[] configuredDNSServers = {"8.8.8.8", "8.8.4.4"};

    /**
     * Registers the extension with Burp Suite.
     *
     * @param callbacks Burp's extender callbacks
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName("SpoofProof"); // Updated Name

        // Initialize UI and context menu in the Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            callbacks.addSuiteTab(this);
            callbacks.registerContextMenuFactory(this);
        });

        stdout.println("SpoofProof extension initialized successfully."); // Updated Log
        stdout.println("Created by Chetanya Sharma aka AggressiveUser.");
        stdout.println("GitHUB: https://github.com/AggressiveUser");
        stdout.println("LinkedIn: https://www.linkedin.com/in/aggressiveuser/");
        stdout.println("X (Twitter): https://x.com/AggressiveUserX");
    }

    /**
     * Sets up the main UI components of the extension.
     *
     * @return The main JPanel containing all UI elements
     */
    private JPanel setupUI() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);

        // ------------------------------
        // Domain Scan Panel
        // ------------------------------
        JPanel domainScanPanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); // Align components to left
        domainInput = new JTextField(30);
        JButton scanButton = new JButton("Domain Scan");

        // Action Listener for Scan Button
        scanButton.addActionListener(e -> {
            String domain = domainInput.getText().trim();
            if (!domain.isEmpty()) {
                if (isValidDomain(domain)) {
                    executorService.submit(() -> checkDomain(domain, null));
                } else {
                    callbacks.printOutput("Invalid domain format entered: " + domain);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Invalid domain format. Please enter a valid domain.", "Input Error", JOptionPane.ERROR_MESSAGE));
                }
            } else {
                callbacks.printOutput("Please enter a valid domain.");
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Please enter a valid domain.", "Input Error", JOptionPane.ERROR_MESSAGE));
            }
        });

        // Set button color to orange and text color to white
        scanButton.setBackground(new Color(255, 165, 0)); // Orange color
        scanButton.setForeground(Color.WHITE); // White text color for contrast

        domainScanPanel.add(new JLabel("Enter Domain:"));
        domainScanPanel.add(domainInput);
        domainScanPanel.add(scanButton);

        mainPanel.add(domainScanPanel, BorderLayout.NORTH);

        // ------------------------------
        // Records Table Setup
        // ------------------------------
        String[] columnNames = {"Record Type", "Record Data", "Recommendation"};
        Object[][] data = {{"DMARC", "", ""}, {"SPF", "", ""}, {"DKIM", "", ""}, {"Final Verdict", "", ""}};
        table = new JTable(data, columnNames) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make cells non-editable
            }
        };

        // Set table properties for enhanced appearance

        table.setFillsViewportHeight(true);
        table.setRowHeight(30);
        table.setShowGrid(true);
        table.setGridColor(new Color(200, 200, 200)); // Subtle gray grid lines
        table.setIntercellSpacing(new Dimension(1, 1)); // Minimal spacing between cells
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // Disable auto-resizing

        // Adjust column widths for better data display
        table.getColumnModel().getColumn(0).setPreferredWidth(100); // Record Type
        table.getColumnModel().getColumn(1).setPreferredWidth(300); // Record Data
        table.getColumnModel().getColumn(2).setPreferredWidth(400); // Recommendation

        // Apply Custom Renderer to all columns
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(new CustomTableCellRenderer());
        }

        // Center-align text in the "Record Type" column
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer); // Center align the "Record Type" column


        JScrollPane tableScrollPane = new JScrollPane(table);
        tabbedPane.addTab("Records", tableScrollPane);

        // ------------------------------
        // About Tab Setup Using Individual JLabels
        // ------------------------------
        JPanel aboutPanel = new JPanel();
        aboutPanel.setLayout(new BoxLayout(aboutPanel, BoxLayout.Y_AXIS));
        aboutPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20)); // Padding around the panel
        aboutPanel.setBackground(new Color(249, 249, 249)); // Equivalent to #f9f9f9

        // Logo and Title Panel
        JPanel logoTitlePanel = new JPanel();
        logoTitlePanel.setLayout(new BoxLayout(logoTitlePanel, BoxLayout.X_AXIS));
        logoTitlePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        logoTitlePanel.setBackground(new Color(249, 249, 249)); // Match parent background

        // Load the logo image from resources
        URL logoURL = getClass().getResource("/images/logo.png"); // Ensure the path is correct
        JLabel logoLabel = new JLabel();
        if (logoURL != null) {
            ImageIcon logoIcon = new ImageIcon(logoURL);
            // Optionally, scale the image to desired size
            Image img = logoIcon.getImage().getScaledInstance(200, -1, Image.SCALE_SMOOTH);
            logoIcon = new ImageIcon(img);
            logoLabel.setIcon(logoIcon);
            logoLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 20)); // Right margin
        } else {
            callbacks.printError("Logo image not found at /images/logo.png");
        }

        // Title and Info Panel
        JPanel titleInfoPanel = new JPanel();
        titleInfoPanel.setLayout(new BoxLayout(titleInfoPanel, BoxLayout.Y_AXIS));
        titleInfoPanel.setBackground(new Color(249, 249, 249)); // Match parent background

        JLabel titleLabel = new JLabel("SpoofProof");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(new Color(255, 165, 0)); // Orange color
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel creatorLabel = new JLabel("Created by: Chetanya Sharma (AggressiveUser)");
        creatorLabel.setFont(new Font("Arial", Font.PLAIN, 14));
        creatorLabel.setForeground(new Color(102, 102, 102)); // #666666
        creatorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        creatorLabel.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0)); // Top margin

        JLabel versionLabel = new JLabel("Version 1.0 | © 2024");
        versionLabel.setFont(new Font("Arial", Font.PLAIN, 14));
        versionLabel.setForeground(new Color(102, 102, 102)); // #666666
        versionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        versionLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0)); // Top margin

        titleInfoPanel.add(titleLabel);
        titleInfoPanel.add(creatorLabel);
        titleInfoPanel.add(versionLabel);

        logoTitlePanel.add(logoLabel);
        logoTitlePanel.add(titleInfoPanel);

        // Description Text using JEditorPane
        JEditorPane descriptionText = new JEditorPane();
        descriptionText.setContentType("text/html");
        descriptionText.setEditable(false);
        descriptionText.setOpaque(false);
        // descriptionText.setEditorKit(kit);
        descriptionText.setText(
                "<html>"
                        + "<body style='margin: 0; padding: 0; text-align: left;'>"
                        + "<h3 style='margin: 0; padding: 0; font-family: Arial; font-size: 14px; font-weight: bold; color: #FFA500;'>Description</h3>"
                        + "<p style='margin: 0; padding: 0; font-size: 11px;'>SpoofProof is a user-friendly Burp Suite extension designed to analyze email security configurations.</p>"
                        + "<p style='margin: 0; padding: 0; font-size: 11px;'>It performs checks on DMARC, SPF, and DKIM records to enhance email authentication and protect against domain spoofing.</p>"
                        + "<p style='margin: 0; padding: 0; font-size: 11px;'>This tool is essential for security professionals aiming to secure email domains from unauthorized use.</p>"
                        + "<p style='margin: 10px 0 0 0; font-weight: bold;'>Third-Party Libraries</p>"
                        + "<p style='margin: 0; font-size: 7px;'>"
                        + "This extension uses the <a href='https://www.dnsjava.org/'>dnsjava</a> library, licensed under the BSD 3-Clause License, "
                        + "ensuring compatibility and flexibility for users uploading it to Burp Suite."
                        + "</p>"
                        + "</body>"
                        + "</html>"
        );
        descriptionText.setAlignmentX(Component.LEFT_ALIGNMENT);
        //descriptionText.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0)); // Bottom margin



        // Add all components to the About Panel
        aboutPanel.add(logoTitlePanel);
        aboutPanel.add(descriptionText);

        // Wrap the About Panel in a JScrollPane
        JScrollPane aboutScroll = new JScrollPane(aboutPanel);
        aboutScroll.setBorder(BorderFactory.createEmptyBorder());
        aboutScroll.setOpaque(false);
        aboutScroll.getViewport().setOpaque(false);
        tabbedPane.addTab("About", aboutScroll);

        // ------------------------------
        // Settings Tab Setup
        // ------------------------------
        JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); // Align components to left
        JTextField dnsInput = new JTextField(String.join(",", configuredDNSServers), 30);
        JButton saveButton = new JButton("Save DNS Settings");

        // Action Listener for Save Button
        saveButton.addActionListener(e -> {
            String dnsSettings = dnsInput.getText().trim();
            if (!dnsSettings.isEmpty()) {
                String[] servers = dnsSettings.split(",");
                List<String> dnsList = new ArrayList<>();
                boolean allValid = true;
                for (String server : servers) {
                    String trimmedServer = server.trim();
                    if (isValidIPAddress(trimmedServer)) {
                        dnsList.add(trimmedServer);
                    } else {
                        allValid = false;
                        callbacks.printOutput("Invalid DNS server IP entered: " + trimmedServer);
                        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Invalid DNS server IP: " + trimmedServer, "Input Error", JOptionPane.ERROR_MESSAGE));
                        break;
                    }
                }
                if (allValid) {
                    this.configuredDNSServers = dnsList.toArray(new String[0]);
                    callbacks.printOutput("DNS Settings updated to: " + dnsSettings);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "DNS Settings updated successfully.", "Settings Saved", JOptionPane.INFORMATION_MESSAGE));
                }
            } else {
                callbacks.printOutput("Please enter valid DNS server IPs.");
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Please enter valid DNS server IPs.", "Input Error", JOptionPane.ERROR_MESSAGE));
            }
        });

        settingsPanel.add(new JLabel("DNS Servers (comma-separated):"));
        settingsPanel.add(dnsInput);
        settingsPanel.add(saveButton);

        tabbedPane.addTab("Settings", settingsPanel);

        // ------------------------------
        // Final Integration
        // ------------------------------
        tabbedPane.setSelectedIndex(0); // Default to "Records" tab
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        return mainPanel;
    }


    /**
     * Provides the tab caption for the Burp Suite UI.
     *
     * @return The tab caption
     */
    @Override
    public String getTabCaption() {
        return "SpoofProof";
    }

    /**
     * Provides the UI component for the Burp Suite tab.
     *
     * @return The main UI component
     */
    @Override
    public Component getUiComponent() {
        return setupUI();
    }

    /**
     * Validates the domain format using a regular expression.
     *
     * @param domain The domain to validate
     * @return True if valid, false otherwise
     */
    private boolean isValidDomain(String domain) {
        String domainRegex = "^(?!-)(?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\\.)+[a-zA-Z]{2,6}$";
        return domain.matches(domainRegex);
    }

    /**
     * Validates the IP address format using a regular expression.
     *
     * @param ip The IP address to validate
     * @return True if valid, false otherwise
     */
    private boolean isValidIPAddress(String ip) {
        String ipRegex = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$";
        return ip.matches(ipRegex);
    }

    /**
     * Sanitizes a string for safe HTML rendering by escaping special characters.
     *
     * @param input The string to sanitize
     * @return The sanitized string
     */
    private String sanitizeForHTML(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    /**
     * Performs DMARC, SPF, and DKIM checks for the specified domain and updates the UI and Burp Issues tab.
     *
     * @param domain       The domain to scan
     * @param httpMessages Optional HTTP messages related to the scan
     */
    private void checkDomain(String domain, IHttpRequestResponse[] httpMessages) {
        // Notify user that the scan has started
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Scanning domain: " + domain, "Scan In Progress", JOptionPane.INFORMATION_MESSAGE));

        callbacks.printOutput("Starting checks for domain: " + domain);

        String dmarcRecord = getDMARCRecordWithFallback(domain);
        String spfRecord = getSPFRecordWithFallback(domain);
        String dkimRecord = getDKIMRecordWithFallback(domain);

        String dmarcRecommendation = generateDMARCRecommendation(dmarcRecord);
        String spfRecommendation = generateSPFRecommendation(spfRecord);
        String dkimRecommendation = generateDKIMRecommendation(dkimRecord);

        // Generate the verdict
        String verdict = determineSpoofingRisk(dmarcRecord, spfRecord, dkimRecord, domain);
        System.out.println("Final Verdict: " + verdict); // Debug statement

        // Update the UI table with sanitized data for records and formatted verdict
        SwingUtilities.invokeLater(() -> {
            table.setValueAt(dmarcRecord != null ? sanitizeForHTML(dmarcRecord) : "Not found", 0, 1);
            table.setValueAt(dmarcRecommendation, 0, 2);
            table.setValueAt(spfRecord != null ? sanitizeForHTML(spfRecord) : "Not found", 1, 1);
            table.setValueAt(spfRecommendation, 1, 2);
            table.setValueAt(dkimRecord != null ? sanitizeForHTML(dkimRecord) : "Not found", 2, 1);
            table.setValueAt(dkimRecommendation, 2, 2);

            // Set the Final Verdict without <html> tags; renderer will handle bold formatting and background color
            table.setValueAt(verdict, 3, 1);
            System.out.println("Set Final Verdict cell to: " + verdict); // Debug statement
        });

        callbacks.printOutput("Final Verdict for " + domain + ": " + verdict);

        try {
            URI issueURI = new URI("http", domain, "/", null);
            URL issueURL = issueURI.toURL();
            IHttpService httpService;
            IHttpRequestResponse[] messages;

            if (httpMessages != null && httpMessages.length > 0) {
                httpService = httpMessages[0].getHttpService();
                messages = httpMessages;
            } else {
                httpService = helpers.buildHttpService(domain, 80, "http");
                messages = new IHttpRequestResponse[0];
            }

            // Create a custom scan issue with sanitized and HTML-formatted details
            String issueDetail = "<b>Domain:</b> " + sanitizeForHTML(domain) + "<br/>"
                    + "<b>DMARC Record:</b> " + (dmarcRecord != null ? sanitizeForHTML(dmarcRecord) : "Not found") + "<br/>"
                    + "<b>SPF Record:</b> " + (spfRecord != null ? sanitizeForHTML(spfRecord) : "Not found") + "<br/>"
                    + "<b>DKIM Record:</b> " + (dkimRecord != null ? sanitizeForHTML(dkimRecord) : "Not found") + "<br/>"
                    + "<b>Final Verdict:</b> " + sanitizeForHTML(verdict);

            CustomScanIssue issue = new CustomScanIssue(
                    httpService,
                    issueURL,
                    messages,
                    "SpoofProof Security Check for " + sanitizeForHTML(domain), // Updated Issue Name
                    issueDetail, // HTML-formatted detail including domain
                    "Information",
                    "Certain",
                    "Update DNS records to ensure DMARC, SPF, and DKIM are configured correctly.",
                    "DMARC, SPF, and DKIM checks for email security.",
                    "To enhance email security, set DMARC policies to “reject” to block unauthorized emails, and regularly update SPF records to include only approved mail servers. Use DKIM with a minimum key length of 2048 bits for all outgoing emails.\n" +
                            "Monitor DMARC reports to detect unauthorized use and regularly audit DMARC, SPF, and DKIM settings for compliance."
            );

            callbacks.printOutput("Adding issue to Burp's Issues tab for domain: " + domain);
            callbacks.addScanIssue(issue);

            // Notify user that the scan has completed successfully
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Scan completed for domain: " + domain, "Scan Complete", JOptionPane.INFORMATION_MESSAGE));
        } catch (Exception e) {
            callbacks.printError("Error creating issue for domain " + domain + ": " + e.getMessage());
            e.printStackTrace(stderr); // Log the stack trace to stderr

            // Notify user of the error during the scan
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Error scanning domain: " + domain + "\n" + e.getMessage(), "Scan Error", JOptionPane.ERROR_MESSAGE));
        }
    }

    /**
     * Retrieves the DMARC record for the domain, with a fallback to the parent domain if necessary.
     *
     * @param domain The domain to check
     * @return The DMARC record if found, otherwise null
     */
    private String getDMARCRecordWithFallback(String domain) {
        String record = getTXTRecord("_dmarc." + domain, "v=DMARC1");
        if (record == null) {
            String parentDomain = getParentDomain(domain);
            if (!parentDomain.equals(domain)) {
                record = getTXTRecord("_dmarc." + parentDomain, "v=DMARC1");
            }
        }
        return record;
    }

    /**
     * Retrieves the SPF record for the domain, with a fallback to the parent domain if necessary.
     *
     * @param domain The domain to check
     * @return The SPF record if found, otherwise null
     */
    private String getSPFRecordWithFallback(String domain) {
        String record = getTXTRecord(domain, "v=spf1");
        if (record == null) {
            String parentDomain = getParentDomain(domain);
            if (!parentDomain.equals(domain)) {
                record = getTXTRecord(parentDomain, "v=spf1");
            }
        }
        return record;
    }

    /**
     * Retrieves the DKIM record for the domain, with a fallback to the parent domain if necessary.
     *
     * @param domain The domain to check
     * @return The DKIM record if found, otherwise null
     */
    private String getDKIMRecordWithFallback(String domain) {
        String record = getTXTRecord("default._domainkey." + domain, null);
        if (record == null) {
            String parentDomain = getParentDomain(domain);
            if (!parentDomain.equals(domain)) {
                record = getTXTRecord("default._domainkey." + parentDomain, null);
            }
        }
        return record;
    }

    /**
     * Extracts the parent domain from a given domain.
     *
     * @param domain The domain to parse
     * @return The parent domain if applicable, otherwise the original domain
     */
    private String getParentDomain(String domain) {
        try {
            String[] domainParts = domain.split("\\.");
            if (domainParts.length > 2) {
                return domainParts[domainParts.length - 2] + "." + domainParts[domainParts.length - 1];
            } else {
                return domain;
            }
        } catch (Exception e) {
            callbacks.printError("Error parsing domain: " + e.getMessage());
            e.printStackTrace(stderr); // Log the stack trace to stderr
            return domain;
        }
    }

    /**
     * Retrieves a TXT record for a given name and optional prefix.
     *
     * @param name         The DNS name to query
     * @param recordPrefix Optional prefix that the TXT record should start with
     * @return The TXT record if found and matches the prefix, otherwise null
     */
    private String getTXTRecord(String name, String recordPrefix) {
        try {
            // Use configured DNS servers
            Resolver[] resolvers = new Resolver[configuredDNSServers.length];
            for (int i = 0; i < configuredDNSServers.length; i++) {
                SimpleResolver resolver = new SimpleResolver(configuredDNSServers[i]);
                resolver.setTimeout(Duration.ofSeconds(5));
                resolvers[i] = resolver;
            }
            ExtendedResolver extendedResolver = new ExtendedResolver(resolvers);

            Lookup lookup = new Lookup(name, Type.TXT);
            lookup.setResolver(extendedResolver);
            Record[] records = lookup.run();
            if (records != null && lookup.getResult() == Lookup.SUCCESSFUL) {
                for (Record record : records) {
                    if (record instanceof TXTRecord txt) {
                        StringBuilder txtDataBuilder = new StringBuilder();
                        for (Object obj : txt.getStrings()) {
                            txtDataBuilder.append(obj.toString());
                        }
                        String txtData = txtDataBuilder.toString();
                        if (recordPrefix == null || txtData.startsWith(recordPrefix)) {
                            return txtData;
                        }
                    }
                }
            } else {
                callbacks.printError("No TXT records found for " + name + ". Lookup result: " + lookup.getResult());
            }
        } catch (Exception e) {
            callbacks.printError("DNS lookup error for " + name + ": " + e.getMessage());
            e.printStackTrace(stderr); // Log the stack trace to stderr
        }
        return null;
    }

    /**
     * Generates a recommendation based on the DMARC record.
     *
     * @param record The DMARC record
     * @return A recommendation string
     */
    private String generateDMARCRecommendation(String record) {
        if (record != null && record.contains("p=reject")) {
            return "DMARC is configured with 'reject' policy.";
        } else if (record != null && record.contains("p=quarantine")) {
            return "DMARC is configured with 'quarantine' policy. Recommend upgrading to 'reject'.";
        } else if (record != null && record.contains("p=none")) {
            return "DMARC policy is set to 'none'. Recommend changing to 'reject' to prevent spoofing.";
        }
        return "DMARC record missing or policy not set to 'reject'. Consider adding a DMARC record with 'p=reject'.";
    }

    /**
     * Generates a recommendation based on the SPF record.
     *
     * @param record The SPF record
     * @return A recommendation string
     */
    private String generateSPFRecommendation(String record) {
        if (record != null && record.startsWith("v=spf1")) {
            if (record.matches(".*\\s(-all|~all)$")) {
                if (record.endsWith("-all")) {
                    return "SPF record found. Ends with '-all'. Ensure it includes authorized IPs only.";
                } else if (record.endsWith("~all")) {
                    return "SPF record found. Ends with '~all'. Consider changing to '-all' for stricter enforcement.";
                }
            } else {
                return "SPF record found but does not end with '-all' or '~all'. Recommend adding '-all' or '~all'.";
            }
        }
        return "No SPF record found. Add an SPF record with 'v=spf1 ... -all' or '~all' to specify allowed IPs.";
    }

    /**
     * Generates a recommendation based on the DKIM record.
     *
     * @param record The DKIM record
     * @return A recommendation string
     */
    private String generateDKIMRecommendation(String record) {
        if (record != null) {
            return "DKIM record found. Ensure it includes all sending domains and uses strong keys.";
        }
        return "No DKIM record found. Add a DKIM record to sign outgoing messages for authenticity.";
    }

    /**
     * Determines the spoofing risk based on DMARC, SPF, and DKIM records.
     *
     * @param dmarc  The DMARC record
     * @param spf    The SPF record
     * @param dkim   The DKIM record
     * @param domain The domain being assessed
     * @return A risk assessment string including the domain name
     */
    private String determineSpoofingRisk(String dmarc, String spf, String dkim, String domain) {
        boolean dmarcReject = dmarc != null && dmarc.contains("p=reject");
        boolean spfFail = spf != null && spf.endsWith("-all");
        boolean spfSoftFail = spf != null && spf.endsWith("~all");
        boolean dkimValid = dkim != null;

        if (!dmarcReject && (spfSoftFail || !spfFail) && !dkimValid) {
            return "High Risk:  " + domain + " is vulnerable to spoofing due to inadequate or absent DMARC, SPF, and DKIM configurations.";
        }
        if (dmarcReject && spfFail && dkimValid) {
            return "Secure:  " + domain + " is protected against spoofing.";
        }
        if (dmarcReject && (spfFail || spfSoftFail) && dkimValid) {
            return "Moderate Risk:  " + domain + " has partial protection against spoofing. Consider strengthening DMARC and SPF.";
        }
        return "Moderate Risk:  " + domain + " has partial protection against spoofing. Consider strengthening DMARC, SPF, and DKIM.";
    }

    /**
     * Creates context menu items for Burp Suite.
     *
     * @param invocation The context menu invocation
     * @return A list of JMenuItem to add to the context menu
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        JMenuItem sendToSpoofProof = new JMenuItem("Send URL to SpoofProof"); // Updated Text

        sendToSpoofProof.addActionListener(e -> {
            IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
            if (selectedItems != null && selectedItems.length > 0) {
                IHttpRequestResponse messageInfo = selectedItems[0];
                String host = messageInfo.getHttpService().getHost();
                if (isValidDomain(host)) {
                    executorService.submit(() -> checkDomain(host, selectedItems));
                } else {
                    callbacks.printOutput("Invalid domain format selected: " + host);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(null, "Selected URL has an invalid domain: " + host, "Input Error", JOptionPane.ERROR_MESSAGE));
                }
            }
        });

        menuItems.add(sendToSpoofProof); // Updated Variable
        return menuItems;
    }

    /**
     * CustomScanIssue represents a scan issue to be added to Burp Suite's Issues tab.
     */
    public static class CustomScanIssue implements IScanIssue {
        private final IHttpService httpService;
        private final URL url;
        private final IHttpRequestResponse[] httpMessages;
        private final String name;
        private final String detail;
        private final String severity;
        private final String confidence;
        private final String remediation;
        private final String background;
        private final String classification;

        /**
         * Constructor for CustomScanIssue.
         *
         * @param httpService    The HTTP service
         * @param url            The URL related to the issue
         * @param httpMessages   HTTP messages related to the issue
         * @param name           Issue name
         * @param detail         Detailed description
         * @param severity       Severity level
         * @param confidence     Confidence level
         * @param remediation    Remediation advice
         * @param background     Background information
         * @param classification Classification details
         */
        public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name,
                               String detail, String severity, String confidence, String remediation, String background,
                               String classification) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
            this.confidence = confidence;
            this.remediation = remediation;
            this.background = background;
            this.classification = classification;
        }

        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0x08000000; // Custom issue type
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return confidence;
        }

        @Override
        public String getIssueBackground() {
            return background + "<br><br><b>References:</b><br>"
                    + "<ul>"
                    + "<li><a href=\"https://dmarc.org\" target=\"_blank\">DMARC.org</a></li>"
                    + "<li><a href=\"https://www.openspf.org\" target=\"_blank\">OpenSPF</a></li>"
                    + "<li><a href=\"https://www.dkim.org\" target=\"_blank\">DKIM.org</a></li>"
                    + "<li><a href=\"https://support.google.com/a/answer/33786\" target=\"_blank\">Google Workspace</a></li>"
                    + "</ul>"
                    + "<b>Vulnerability Classification:</b><br>"
                    + "<ul>"
                    + "<li><a href=\"https://cwe.mitre.org/data/definitions/290.html\" target=\"_blank\">CWE-290: Authentication Bypass by Spoofing</a></li>"
                    + "<li><a href=\"https://cwe.mitre.org/data/definitions/346.html\" target=\"_blank\">CWE-346: Origin Validation Error</a></li>"
                    + "<li><a href=\"https://cwe.mitre.org/data/definitions/703.html\" target=\"_blank\">CWE-703: Improper Check or Handling of Exceptional Conditions</a></li>"
                    + "<li><a href=\"https://capec.mitre.org/data/definitions/139.html\" target=\"_blank\">CAPEC-139: Bypassing Authentication Schemes</a></li>"
                    + "</ul>";
        }

        @Override
        public String getRemediationBackground() {
            return remediation;
        }

        @Override
        public String getIssueDetail() {
            return detail; // 'detail' contains HTML-formatted string including domain
        }

        @Override
        public String getRemediationDetail() {
            return classification;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }

        /**
         * Implementation of the getHost() method required by the IScanIssue interface.
         *
         * @return The host part of the URL associated with the issue.
         */
        @Override
        public String getHost() {
            return url.getHost();
        }

        @Override
        public String getProtocol() {
            return url.getProtocol();
        }

        @Override
        public int getPort() {
            return url.getPort() == -1 ? (getProtocol().equals("https") ? 443 : 80) : url.getPort();
        }

    }

    /**
     * CustomTableCellRenderer applies bold font to the "Final Verdict" row in the JTable,
     * changes the background color based on the risk severity,
     * and adds borders between cells for a cleaner look.
     */
    public static class CustomTableCellRenderer extends DefaultTableCellRenderer {
        private static final Font BOLD_FONT = new Font("Arial", Font.BOLD, 12);
        private static final Font REGULAR_FONT = new Font("Arial", Font.PLAIN, 12);

        // Define colors for different risk levels
        private static final Color SECURE_COLOR = new Color(144, 238, 144); // Light Green
        private static final Color MODERATE_RISK_COLOR = new Color(255, 255, 102); // Light Yellow
        private static final Color HIGH_RISK_COLOR = new Color(255, 102, 102); // Light Red
        private static final Color DEFAULT_COLOR = Color.WHITE;

        // Define border styles
        private static final Border CELL_BORDER = BorderFactory.createLineBorder(Color.GRAY, 1);
        private static final Border FINAL_VERDICT_BORDER = BorderFactory.createLineBorder(Color.DARK_GRAY, 2);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            // Use JLabel to handle rendering
            JLabel label = new JLabel();
            label.setOpaque(true); // Must be opaque to show background colors

            // Fetch the "Record Type" from the first column to identify the row
            Object recordTypeObj = table.getValueAt(row, 0);
            String recordType = recordTypeObj != null ? recordTypeObj.toString().toLowerCase() : "";

            // Check if this is the "Final Verdict" row
            boolean isFinalVerdict = recordType.contains("final verdict");

            if (isFinalVerdict && column == 1) { // Apply to "Record Data" column
                // Apply bold font
                label.setFont(BOLD_FONT);
                label.setText(value != null ? value.toString() : "");

                // Determine the risk level based on the verdict string
                String verdict = value != null ? value.toString().toLowerCase() : "";

                if (verdict.contains("high risk")) {
                    label.setBackground(HIGH_RISK_COLOR);
                } else if (verdict.contains("moderate risk")) {
                    label.setBackground(MODERATE_RISK_COLOR);
                } else if (verdict.contains("secure")) {
                    label.setBackground(SECURE_COLOR);
                } else {
                    label.setBackground(DEFAULT_COLOR); // Default color if risk level is unidentified
                }

                // Apply a distinct border for the Final Verdict row
                label.setBorder(FINAL_VERDICT_BORDER);
            } else {
                // Apply regular font
                label.setFont(REGULAR_FONT);
                label.setText(value != null ? value.toString() : "");

                // Apply background colors based on row (existing functionality)
                switch (row) {
                    case 0:
                        label.setBackground(new Color(224, 255, 255)); // Light Cyan
                        break;
                    case 1:
                        label.setBackground(new Color(255, 240, 245)); // Lavender Blush
                        break;
                    case 2:
                        label.setBackground(new Color(240, 255, 240)); // Honeydew
                        break;
                    default:
                        label.setBackground(DEFAULT_COLOR);
                        break;
                }

                // Apply a standard border for other rows
                label.setBorder(CELL_BORDER);
            }

            // Handle selection highlighting
            if (isSelected) {
                label.setBackground(table.getSelectionBackground());
                label.setForeground(table.getSelectionForeground());
            } else {
                label.setForeground(Color.BLACK);
            }

            return label;
        }
    }

}
