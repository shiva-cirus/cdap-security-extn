/*
 * Copyright © 2016 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.cdap.cdap.security.authorization.ldap;

/**
 * This class holds information for LDAP search.
 */
final class SearchConfig {

  private final String baseDn;
  private final String objectClass;
  private final String memberAttribute;
  private final String nameAttribute;
  private final String adminValue;

  SearchConfig(String baseDn, String objectClass, String memberAttribute, String nameAttribute, String adminValue) {
    this.baseDn = baseDn;
    this.objectClass = objectClass;
    this.memberAttribute = memberAttribute;
    this.nameAttribute = nameAttribute;
    this.adminValue = adminValue;
  }

  String getBaseDn() {
    return baseDn;
  }

  String getObjectClass() {
    return objectClass;
  }

  String getMemberAttribute() {
    return memberAttribute;
  }

  String getNameAttribute() {
    return nameAttribute;
  }

  String getAdminValue() { return adminValue; }
}
