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

import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.InstanceId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.id.NamespacedEntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Authorizable;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.spi.authorization.AbstractAuthorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.FileHandler;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * An implementation of {@link Authorizer} using LDAP as the backing store.
 */
public class LDAPAuthorizer extends AbstractAuthorizer {

  private static final Logger LOG = LoggerFactory.getLogger(LDAPAuthorizer.class);
  private static final String CREDENTIALS_KEY_NAME = "credentialsKeyName";

  private static final String USER_BASE_DN = "userBaseDn";
  private static final String USER_RDN_ATTRIBUTE = "userRdnAttribute";
  private static final String USER_OBJECT_CLASS = "userObjectClass";
  private static final String USER_ID_ATTRIBUTE = "userIdAttribute";
  private static final String SEARCH_RECURSIVE = "searchRecursive";
  private static final String ENFORCE_EXTVALIDATION = "enforceExtendedValidation";
  private static final String SYSTEM = "system";
  private static final int MAX_RETRY_COUNT = 4;
  private static final int RETRY_WAIT_INTERVAL_MS = 100;

  private DirContext dirContext;
  private SearchConfig instanceSearchConfig;
  private SearchConfig namespaceSearchConfig;
  private String[] userBaseDNList = null;
  private String userRdnAttribute;
  private String userObjectClass;
  private String userIdAttribute;
  private boolean searchRecursive;
  private boolean enforceExtendedValidation;
  private Principal systemPrincipal;
  private FileHandler handler = null;
  private Hashtable<String, Object> env = null;


  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    super.initialize(context);

    Properties properties = context.getExtensionProperties();
    String providerUrl = properties.getProperty(Context.PROVIDER_URL);
    if (providerUrl == null) {
      throw new IllegalArgumentException("Missing provider url configuration '" + Context.PROVIDER_URL + "'");
    }
    if (!providerUrl.startsWith("ldap://") && !providerUrl.startsWith("ldaps://")) {
      throw new IllegalArgumentException("Unsupported provider '" + providerUrl + "'. Only LDAP is supported.");
    }

    instanceSearchConfig = createSearchConfig(properties, "instance");
    namespaceSearchConfig = createSearchConfig(properties, "namespace");

    String userBaseDn = checkAndGet(properties, USER_BASE_DN);
    userBaseDNList = userBaseDn.split(";");
    userRdnAttribute = checkAndGet(properties, USER_RDN_ATTRIBUTE);
    userObjectClass = checkAndGet(properties, USER_OBJECT_CLASS);
    userIdAttribute = checkAndGet(properties, USER_ID_ATTRIBUTE);

    env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    for (String key : properties.stringPropertyNames()) {
      env.put(key, properties.getProperty(key));
    }

    boolean useSSL = "ssl".equals(properties.getProperty(Context.SECURITY_PROTOCOL))
      || providerUrl.startsWith("ldaps://");

    if (useSSL) {
      env.put("java.naming.ldap.factory.socket", TrustAllSSLSocketFactory.class.getName());
    }

    String credentialsKeyName = properties.getProperty(CREDENTIALS_KEY_NAME);
    if (credentialsKeyName != null) {
      int idx = credentialsKeyName.indexOf(':');
      if (idx < 0) {
        throw new IllegalArgumentException("The '" + CREDENTIALS_KEY_NAME +
                                             "' property must be in the form 'namespace:keyname'");
      }
      Object obj = context.get(credentialsKeyName.substring(0, idx), credentialsKeyName.substring(idx + 1));
      env.put(Context.SECURITY_CREDENTIALS, obj);
    }

    try {
      dirContext = new InitialDirContext(env);
    } catch (Exception e) {
      LOG.error("Exception occurred while connecting.", e);
      throw e;
    }
    searchRecursive = Boolean.getBoolean(SEARCH_RECURSIVE);
    enforceExtendedValidation = Boolean.getBoolean(ENFORCE_EXTVALIDATION);

    systemPrincipal = new Principal(UserGroupInformation.getCurrentUser().getShortUserName(),
                                    Principal.PrincipalType.USER);
    LOG.info("Initialized {} with properties {}. System user is {}.",
             LDAPAuthorizer.class.getSimpleName(), properties, systemPrincipal);
  }

  @Override
  public void destroy() throws Exception {
    LOG.info("In destroy method connection getting closed");
    if (dirContext != null)
      dirContext.close();
  }


  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    //Vodafone Requirements as to limit the users to specific Namespaces. A user given access to namespace have
    // full access to all the functionality in the namespace.  There is no implementation required for now.
    // In future if VF needs to extend and restrict to specific objects like Read Only or to specific pipelines etc.
    LOG.debug("In enforce for entity: " + entityId.getEntityName() + " ,for principal: " + principal.getName());
    if (entityId instanceof NamespacedEntityId) {
      validateLDAP(entityId, principal, actions);
    } else {
      if (enforceExtendedValidation) {
        throw new IllegalArgumentException("Unsupported entity type '" + entityId.getClass() +
                                             "' of entity '" + entityId + "'.");
      }
    }
  }

  public void validateLDAP(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {

    LOG.debug("In validateLDAP : " + entityId.getEntityName() + " ,for principal: " + principal.getName());
    Thread.currentThread().setContextClassLoader(LDAPAuthorizer.class.getClassLoader());

    if (("hadoop").equalsIgnoreCase(principal.getName()) ||
      ("cdap").equalsIgnoreCase(principal.getName())) {
      //skip validation for hadoop and cdap user
      LOG.debug("In validateLDAP, skipping validation for entity: " + entityId.getEntityName()
                  + " ,for principal: " + principal.getName());
      return;
    }

    // Special case for system user that it can always access system namespace
    if (systemPrincipal.equals(principal)) {
      // if (systemPrincipal.getName() == principal.getName()) {
      LOG.debug("In validateLDAP, skipping validation for entity: " + entityId.getEntityName()
                  + " ,for principal: " + principal.getName());
      return;
    }

    String filter = "(&(objectClass={0})({1}={2})(|(({3}={4})({5}={6}))))";
    SearchConfig searchConfig;
    String entityName;

    // Based on the requested EntityId, use different search config
    if (entityId instanceof InstanceId) {
      // Query for membership of the given principal in the instance
      searchConfig = instanceSearchConfig;
      entityName = ((InstanceId) entityId).getInstance();
    } else if (entityId instanceof NamespacedEntityId) {
      // Query for the membership of the given principal in the namespace
      searchConfig = namespaceSearchConfig;
      entityName = ((NamespacedEntityId) entityId).getNamespace();
    } else {
      throw new IllegalArgumentException("Unsupported entity type '" + entityId.getClass() +
                                           "' of entity '" + entityId + "'.");
    }

    if (entityName.equalsIgnoreCase(SYSTEM)) {
      //Allow access to services like Wrangler etc
      return;
    }
    SearchControls searchControls = new SearchControls();
    searchControls.setDerefLinkFlag(true);
    if (searchRecursive) {
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    for (String searchDNs : userBaseDNList) {

      Object[] filterArgs = new Object[]{
        userObjectClass, userIdAttribute, principal.getName(), searchConfig.getMemberAttribute(),
        String.format("%s=%s,%s", searchConfig.getRdnAttribute(), entityName, searchConfig.getBaseDn(),
                      searchConfig.getMemberAttribute()), searchConfig.getMemberAttribute(),
        String.format("%s=%s,%s", searchConfig.getRdnAttribute(), searchConfig.getAdminValue(),
                      searchConfig.getBaseDn())
      };
      NamingEnumeration<SearchResult> results = null;
      boolean retry = true;
      while (retry) {
        try {
          results = dirContext.search(searchDNs,
                                      filter, filterArgs, searchControls);
          retry = false;
        } catch (CommunicationException ce) {
          // Retry connection
          if (retryConnection() == null) {
            LOG.error("Error is: " + ce.getMessage());
            throw ce;
          }
        } catch (Exception e) {
          LOG.error(e.toString(), e);
          throw e;
        }
      }
      try {
        if (results.hasMore()) {
          return;
        }
      } finally {
        results.close();
      }
    }
    LOG.warn("Unauthorized Access for user .  " + principal + "on entity " + entityId);
    throw new UnauthorizedException(principal, actions, entityId);
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    Set<Privilege> privileges = new LinkedHashSet<>();
    String filter = "(&(objectClass={0})({1}={2}))";
    int i = 1;
    // Query for all instances and namespaces that the given principal is a member of
    for (SearchConfig searchConfig : Arrays.asList(instanceSearchConfig, namespaceSearchConfig)) {
      for (String searchDNs : userBaseDNList) {
        Object[] filterArgs = new Object[]{
          searchConfig.getObjectClass(), searchConfig.getMemberAttribute(),
          String.format("%s=%s,%s", userRdnAttribute, principal.getName(), searchDNs)
        };
        SearchControls searchControls = new SearchControls();
        searchControls.setDerefLinkFlag(true);
        searchControls.setReturningAttributes(new String[]{searchConfig.getNameAttribute()});
        if (searchRecursive) {
          searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        }
        NamingEnumeration<SearchResult> results = null;
        try {

          results = dirContext.search(searchConfig.getBaseDn(),
                                      filter, filterArgs, searchControls);

          // When a user is in a given group, then he is allowed to perform all action in that group
          while (results.hasMore()) {
            SearchResult result = results.next();
            Attribute attribute = result.getAttributes().get(searchConfig.getNameAttribute());
            if (attribute != null) {
              String entityName = attribute.get().toString();
              for (Action action : Action.values()) {
                privileges.add(new Privilege(createEntity(searchConfig, entityName), action));
              }
            }
          }
        } catch (Exception e) {
          if (i == 1) {
            i++;
          } else {
            throw e;
          }
        } finally {
          results.close();
        }
      }
    }

    // Special case for system user that it can always access system namespace
    if (systemPrincipal.equals(principal)) {
      for (Action action : Action.values()) {
        privileges.add(new Privilege(NamespaceId.SYSTEM, action));
      }
    }

    return privileges;
  }

  @Override
  public void createRole(Role role) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("createRole not support");
  }

  @Override
  public void dropRole(Role role) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("dropRole not support");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("addRoleToPrincipal not support");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("removeRoleFromPrincipal not support");
  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("listRoles not support");
    return Collections.emptySet();
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("listRoles not support");
    return Collections.emptySet();
  }

  @Override
  public void grant(Authorizable arg0, Principal arg1, Set<Action> arg2) throws Exception {
    // TODO Auto-generated method stub

  }

  @Override
  public void revoke(Authorizable arg0) throws Exception {
    // TODO Auto-generated method stub

  }

  @Override
  public void revoke(Authorizable arg0, Principal arg1, Set<Action> arg2) throws Exception {
    // TODO Auto-generated method stub

  }


  private String checkAndGet(Properties properties, String key) {
    String value = properties.getProperty(key);
    if (value == null) {
      throw new IllegalArgumentException("Property '" + key + "' is missing");
    }
    return value;
  }

  private SearchConfig createSearchConfig(Properties properties, String keyPrefix) throws Exception {
    String baseDn = checkAndGet(properties, keyPrefix + "BaseDn");
    String objectClass = checkAndGet(properties, keyPrefix + "ObjectClass");
    String memberAttribute = checkAndGet(properties, keyPrefix + "MemberAttribute");
    String nameAttribute = checkAndGet(properties, keyPrefix + "NameAttribute");
    String adminValue = checkAndGet(properties, keyPrefix + "Admin");
    String rdnAttribute = checkAndGet(properties, keyPrefix + "RdnAttribute");
    LOG.debug("In create Search config for keyPrefix:" + keyPrefix
                + "baseDn:" + baseDn + "ObjectClass:" + objectClass
                + "memberAttribute:" + memberAttribute + "nameAttribute:" + nameAttribute);
    return new SearchConfig(baseDn, objectClass, memberAttribute, nameAttribute, adminValue, rdnAttribute);
  }

  private EntityId createEntity(SearchConfig searchConfig, String id) {
    if (searchConfig == instanceSearchConfig) {
      return new InstanceId(id);
    } else if (searchConfig == namespaceSearchConfig) {
      return new NamespaceId(id);
    }
    // Shouldn't happen
    throw new IllegalArgumentException("Unknown SearchConfig: " + searchConfig);
  }

  private DirContext retryConnection() {
    LOG.debug("Starting Connection Retry. Will try for "+MAX_RETRY_COUNT +
                " with exponential wait times starting at " + RETRY_WAIT_INTERVAL_MS);
    int delayCounter = RETRY_WAIT_INTERVAL_MS;
    for (int rty = 0; rty < MAX_RETRY_COUNT; rty++) {
      try {
        LOG.debug("Sleeping for (ms)" + delayCounter);
        Thread.sleep(delayCounter);
        dirContext = new InitialDirContext(env);
        return dirContext;
      } catch (CommunicationException ce) {
        delayCounter = delayCounter * 2;
      } catch (Exception e) {
        LOG.error(e.toString(), e);
        break;
      }
    }
    return null;
  }

  @Override
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {

    LOG.debug("Inside Is Visible " + entityIds);

    Set<EntityId> visibleEntities = new HashSet<>(entityIds.size());
    Set<Action> validateAction = new HashSet<>(1);
    validateAction.add(Action.ADMIN);
    for (EntityId entityId : entityIds) {
      if (entityId instanceof NamespacedEntityId) {
        try {
          validateLDAP(entityId, principal, validateAction);
          visibleEntities.add(entityId);
        } catch (Exception ex) {
          //No action needed as name space will not be visibile
        }
      } else {
        visibleEntities.add(entityId);
      }
    }
    return visibleEntities;
  }
}
