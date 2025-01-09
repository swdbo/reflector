package burp;

import javax.swing.table.AbstractTableModel;
import java.util.*;

public class ParameterTableModel extends AbstractTableModel {
    private static final String[] COLUMN_NAMES = {
        "Name", "Type", "Requests", "Unique URLs", "Unique Values", "Reflected times", "Example Value"
    };
    
    private class ParameterData {
        String name;
        String type;
        Set<String> urls = new HashSet<>();
        Set<String> values = new HashSet<>();
        int reflectionCount = 0;
        String exampleValue;
        
        ParameterData(String name, String type, String value) {
            this.name = name;
            this.type = type;
            this.exampleValue = value;
        }
    }
    
    private Map<String, ParameterData> parameters = new HashMap<>();
    private List<String> parameterNames = new ArrayList<>();
    
    @Override
    public int getRowCount() {
        return parameterNames.size();
    }
    
    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }
    
    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }
    
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= parameterNames.size()) {
            return null;
        }
        
        String paramName = parameterNames.get(rowIndex);
        ParameterData data = parameters.get(paramName);
        
        switch (columnIndex) {
            case 0: return data.name;
            case 1: return data.type;
            case 2: return data.values.size(); // Number of requests (unique values)
            case 3: return data.urls.size();   // Number of unique URLs
            case 4: return data.values.size(); // Number of unique values
            case 5: return data.reflectionCount; // Total reflection count
            case 6: return data.exampleValue;
            default: return null;
        }
    }
    
    public void updateParameter(String name, String type, String value, String url, List<int[]> matches) {
        ParameterData data = parameters.computeIfAbsent(name, k -> {
            ParameterData newData = new ParameterData(k, type, value);
            parameterNames.add(k);
            return newData;
        });
        
        data.urls.add(url);
        data.values.add(value);
        if (matches != null) {
            data.reflectionCount += matches.size();
        }
        
        // Update example value if current one is empty or new value is more interesting
        if (data.exampleValue == null || data.exampleValue.isEmpty() || 
            (value != null && value.length() > data.exampleValue.length())) {
            data.exampleValue = value;
        }
        
        // Notify table of data change
        fireTableDataChanged();
    }
    
    public void clear() {
        parameters.clear();
        parameterNames.clear();
        fireTableDataChanged();
    }
}
