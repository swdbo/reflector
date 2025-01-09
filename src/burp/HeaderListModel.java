package burp;

import javax.swing.DefaultListModel;

public class HeaderListModel extends DefaultListModel<String> {
    
    public HeaderListModel() {
        // Add default headers
        addElement("X-Forwarded-For");
        addElement("X-Forwarded-Host");
        addElement("X-API-Key");
        addElement("X-Lol");
    }
    
    @Override
    public void addElement(String header) {
        // Convert to lowercase for case-insensitive comparison
        String normalizedHeader = header.trim().toLowerCase();
        
        // Check if header already exists (case-insensitive)
        for (int i = 0; i < getSize(); i++) {
            if (getElementAt(i).toLowerCase().equals(normalizedHeader)) {
                return; // Skip duplicate
            }
        }
        
        // Add header in original case if not duplicate
        super.addElement(header.trim());
    }
    
    public boolean contains(String header) {
        String normalizedHeader = header.trim().toLowerCase();
        for (int i = 0; i < getSize(); i++) {
            if (getElementAt(i).toLowerCase().equals(normalizedHeader)) {
                return true;
            }
        }
        return false;
    }
}
