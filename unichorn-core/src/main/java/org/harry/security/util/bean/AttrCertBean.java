package org.harry.security.util.bean;

import iaik.asn1.ObjectID;

public class AttrCertBean {

    String roleName;

    String commonName;

    String  targetName;

    String [] targetNames;

    String targetGroup;

    String authCountry;
    String authOrganization;
    String authOrganizationalUnit;
    String authCommonName;

    String category;

    String accessIdentityService;

    String accessIdentityIdent;

    String groupValue1;

    String groupValue2;



    public String getRoleName() {
        return roleName;
    }

    public AttrCertBean setRoleName(String roleName) {
        this.roleName = roleName;
        return this;
    }

    public String getCommonName() {
        return commonName;
    }

    public AttrCertBean setCommonName(String commonName) {
        this.commonName = commonName;
        return this;
    }

    public String getTargetName() {
        return targetName;
    }

    public AttrCertBean setTargetName(String targetName) {
        this.targetName = targetName;
        return this;
    }

    public String[] getTargetNames() {
        return targetNames;
    }

    public AttrCertBean setTargetNames(String[] targetNames) {
        this.targetNames = targetNames;
        return this;
    }

    public String getTargetGroup() {
        return targetGroup;
    }

    public AttrCertBean setTargetGroup(String targetGroup) {
        this.targetGroup = targetGroup;
        return this;
    }

    public String getAuthCountry() {
        return authCountry;
    }

    public AttrCertBean setAuthCountry(String authCountry) {
        this.authCountry = authCountry;
        return this;
    }

    public String getAuthOrganization() {
        return authOrganization;
    }

    public AttrCertBean setAuthOrganization(String authOrganization) {
        this.authOrganization = authOrganization;
        return this;
    }

    public String getAuthOrganizationalUnit() {
        return authOrganizationalUnit;
    }

    public AttrCertBean setAuthOrganizationalUnit(String authOrganizationalUnit) {
        this.authOrganizationalUnit = authOrganizationalUnit;
        return this;
    }

    public String getAuthCommonName() {
        return authCommonName;
    }

    public AttrCertBean setAuthCommonName(String authCommonName) {
        this.authCommonName = authCommonName;
        return this;
    }

    public String getCategory() {
        return category;
    }

    public AttrCertBean setCategory(String category) {
        this.category = category;
        return this;
    }

    public String getAccessIdentityService() {
        return accessIdentityService;
    }

    public AttrCertBean setAccessIdentityService(String accessIdentityService) {
        this.accessIdentityService = accessIdentityService;
        return this;
    }

    public String getAccessIdentityIdent() {
        return accessIdentityIdent;
    }

    public AttrCertBean setAccessIdentityIdent(String accessIdentityIdent) {
        this.accessIdentityIdent = accessIdentityIdent;
        return this;
    }

    public String getGroupValue1() {
        return groupValue1;
    }

    public AttrCertBean setGroupValue1(String groupValue1) {
        this.groupValue1 = groupValue1;
        return this;
    }

    public String getGroupValue2() {
        return groupValue2;
    }

    public AttrCertBean setGroupValue2(String groupValue2) {
        this.groupValue2 = groupValue2;
        return this;
    }
}
