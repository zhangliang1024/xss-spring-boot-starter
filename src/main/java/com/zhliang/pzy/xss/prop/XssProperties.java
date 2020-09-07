package com.zhliang.pzy.xss.prop;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.util.CollectionUtils;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@ConfigurationProperties("pzy.xss.filter")
public class XssProperties {

    private boolean enabled = true;
    private int order;
    private String name = "xssFilter";
    private Map<String, String> initParameters = new LinkedHashMap<>();
    private Set<String> servletNames = new LinkedHashSet<>();
    private Set<ServletRegistrationBean<?>> servletRegistrationBeans = new LinkedHashSet<>();
    private Set<String> urlPatterns = new LinkedHashSet<>();


    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        this.order = order;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Map<String, String> getInitParameters() {
        return initParameters;
    }

    public void setInitParameters(Map<String, String> initParameters) {
        this.initParameters = initParameters;
    }

    public Set<String> getServletNames() {
        return servletNames;
    }

    public void setServletNames(Set<String> servletNames) {
        this.servletNames = servletNames;
    }

    public Set<ServletRegistrationBean<?>> getServletRegistrationBeans() {
        return servletRegistrationBeans;
    }

    public void setServletRegistrationBeans(Set<ServletRegistrationBean<?>> servletRegistrationBeans) {
        this.servletRegistrationBeans = servletRegistrationBeans;
    }

    public Set<String> getUrlPatterns() {
        if(CollectionUtils.isEmpty(urlPatterns)){
            urlPatterns.add("/*");
        }
        return urlPatterns;
    }

    public void setUrlPatterns(Set<String> urlPatterns) {
        this.urlPatterns = urlPatterns;
    }
}
