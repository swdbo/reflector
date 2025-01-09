package burp;

public class Pair {
    private int[] pair;
    
    public Pair(int[] pair) {
        this.pair = pair;
    }
    
    public int[] getPair() {
        return pair;
    }
    
    public int getStart() {
        return pair[0];
    }
    
    public int getEnd() {
        return pair[1];
    }
}
