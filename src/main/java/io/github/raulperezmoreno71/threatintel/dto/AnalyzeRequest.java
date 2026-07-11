package io.github.raulperezmoreno71.threatintel.dto;

public class AnalyzeRequest {
    private String url;

    public AnalyzeRequest () {

    }

    public AnalyzeRequest (String url) {
        this.url = url;
    }

    public String getUrl () {
        return this.url;
    }

    public void setUrl (String url) {
        this.url = url;
    }
}
