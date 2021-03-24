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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
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
  private static final String VERIFY_SSL_CERT_PROPERTY = "sslVerifyCertificate";
  private static final String CREDENTIALS_KEY_NAME = "credentialsKeyName";

  private static final String USER_BASE_DN = "userBaseDn";
  private static final String USER_RDN_ATTRIBUTE = "userRdnAttribute";
  private static final String SEARCH_RECURSIVE = "searchRecursive";
  //TCS changes
  private static final String MEMBER_OF = "memberOf";
  private static final String UNIQUE_ID_REPLACE = "{0}";

  private DirContext dirContext;
  private SearchConfig instanceSearchConfig;
  private SearchConfig namespaceSearchConfig;
  private String userBaseDn;
  private String userRdnAttribute;
  private boolean searchRecursive;
  private Principal systemPrincipal;
  private FileHandler handler = null;
  private Map<String, String> userPermissionMap = null;
  private Hashtable<String, Object> env = null;
  private java.util.logging.Logger logger = null;

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    super.initialize(context);
    if (handler == null) {
      handler = new FileHandler("/tmp/auth.log", true);
      handler.setFormatter(new SimpleFormatter());
      logger = java.util.logging.Logger.getLogger("io.cdap.cdap.security.authorization.ldap");
      logger.addHandler(handler);
    }
    logger.info("print values in property");
    Properties properties = context.getExtensionProperties();

    for (Object key : properties.keySet()) {
      //logger.info("key: " + key + " ,value: " + properties.getProperty(key.toString()));
    }

    String providerUrl = properties.getProperty(Context.PROVIDER_URL);
    if (providerUrl == null) {
      throw new IllegalArgumentException("Missing provider url configuration '" + Context.PROVIDER_URL + "'");
    }
    if (!providerUrl.startsWith("ldap://") && !providerUrl.startsWith("ldaps://")) {
      throw new IllegalArgumentException("Unsupported provider '" + providerUrl + "'. Only LDAP is supported.");
    }

    instanceSearchConfig = createSearchConfig(properties, "instance");
    namespaceSearchConfig = createSearchConfig(properties, "namespace");

    userBaseDn = checkAndGet(properties, USER_BASE_DN);
    userRdnAttribute = checkAndGet(properties, USER_RDN_ATTRIBUTE);
    logger.info("userBaseDn: " + this.userBaseDn + " ,useRdnAttribute: " + userRdnAttribute);
    env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    for (String key : properties.stringPropertyNames()) {
      env.put(key, properties.getProperty(key));
    }
		/* commented not needed, certificate is imported
		boolean useSSL = "ssl".equals(properties.getProperty(Context.SECURITY_PROTOCOL))
				|| providerUrl.startsWith("ldaps://");

		if (useSSL && !Boolean.parseBoolean(properties.getProperty(VERIFY_SSL_CERT_PROPERTY))) {
			env.put("java.naming.ldap.factory.socket", TrustAllSSLSocketFactory.class.getName());
		}
		*/
    // Retrieves the actual LDAP credentials from secure store if needed

		/*
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
		*/

    //TCS change
    Enumeration<String> enumeration = env.keys();
    // iterate using enumeration object
    while (enumeration.hasMoreElements()) {
      String key = enumeration.nextElement();
      //logger.info("key in env:" + key + " ,value in env:" + env.get(key));
    }
    try {
      dirContext = new InitialDirContext(env);
    } catch (Exception e) {
      logger.info("Exception occurred while connecting.");
      logger.log(Level.SEVERE, e.toString(), e);
      throw e;
    }
    searchRecursive = Boolean.getBoolean(SEARCH_RECURSIVE);

    systemPrincipal = new Principal(UserGroupInformation.getCurrentUser().getShortUserName(),
                                    Principal.PrincipalType.USER);

    logger.info("systemPrincipal name: " + systemPrincipal.getName() +
                  " ,SystemPrincipleType: " + systemPrincipal.getType());

    LOG.info("Initialized {} with properties {}. System user is {}.",
             LDAPAuthorizer.class.getSimpleName(), properties, systemPrincipal);
  }

  @Override
  public void destroy() throws Exception {
    logger.info("In destroy method connection getting closed");
    dirContext.close();
  }


  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    logger.info("In enforce for entity: " + entityId.getEntityName() + " ,for principal: " + principal.getName());
  }


  public void validateLDAP(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    if (handler == null) {
      handler = new FileHandler("/tmp/auth.log", true);
      logger = java.util.logging.Logger.getLogger("io.cdap.cdap.security.authorization.ldap");
      logger.addHandler(handler);
    }
    InitialDirContext dirContext = null;
    logger.info("In validateLDAP : " + entityId.getEntityName() + " ,for principal: " + principal.getName());

    if (("hadoop").equalsIgnoreCase(principal.getName()) ||
      ("cdap").equalsIgnoreCase(principal.getName())) {
      //skip validation for hadoop and cdap user
      logger.info("In validateLDAP, skipping validation for entity: " + entityId.getEntityName()
                    + " ,for principal: " + principal.getName());
      return;
    }
    String filter = "(&(|({0}={1})({2}={3}))(objectClass={4})({5}={6}))";
    SearchConfig searchConfig;
    String entityName;

    // Special case for system user that it can always access system namespace
     if (systemPrincipal.equals(principal)) {
    // if (systemPrincipal.getName() == principal.getName()) {
      logger.info("In validateLDAP, skipping validation for entity: " + entityId.getEntityName()
                    + " ,for principal: " + principal.getName());
      return;
    }

    // Based on the requested EntityId, use different search config
    if (entityId instanceof InstanceId) {
      // Query for membership of the given principal in the instance
      searchConfig = instanceSearchConfig;
      entityName = ((InstanceId) entityId).getInstance();
      logger.info("Entity is  InstanceId");
    } else if (entityId instanceof NamespacedEntityId) {
      // Query for the membership of the given principal in the namespace
      searchConfig = namespaceSearchConfig;
      entityName = ((NamespacedEntityId) entityId).getNamespace();
      logger.info("Entity is  NamespacedEntityId");
    } else {
      throw new IllegalArgumentException("Unsupported entity type '" + entityId.getClass() +
                                           "' of entity '" + entityId + "'.");
    }
    logger.info("In validateLDAP original code of dir contect search before filter args");
    // Search for the user group membership
    Object[] filterArgs = new Object[]{
      searchConfig.getNameAttribute(), entityName, searchConfig.getNameAttribute(),
      searchConfig.getAdminValue(), searchConfig.getObjectClass(), searchConfig.getMemberAttribute(),
      String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
    };
    logger.info("In validateLDAP original code of dir contect search after filter args");
    SearchControls searchControls = new SearchControls();
    searchControls.setDerefLinkFlag(true);
    if (searchRecursive) {
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }
    logger.info("In validateLDAP before original code of dir contect search ");
    logger.info("search configbasedn: " + searchConfig.getBaseDn() + " ,filter:" + filter);
    for (Object obj : filterArgs) {
      logger.info("filter args: " + obj.toString());
    }
    logger.info("In validateLDAP till end of original code ");
    NamingEnumeration<SearchResult> results = null;
    boolean isErrorOccurred = false;
    try {
      dirContext = new InitialDirContext(env);
      results = dirContext.search(searchConfig.getBaseDn(),
                                  filter, filterArgs, searchControls);
    } catch (CommunicationException ce) {
      isErrorOccurred = true;
      logger.info("Communication error occured");
      if (null != ce.getMessage()) {
        logger.info("Error is: " + ce.getMessage());
      }
      logger.log(Level.SEVERE, ce.toString(), ce);
      throw ce;
    } catch (Exception e) {
      isErrorOccurred = true;
      logger.info("Communication error occured.");
      logger.log(Level.SEVERE, e.toString(), e);
      throw e;
    } finally {
      if (isErrorOccurred && dirContext != null) {
        dirContext.close();
      }
    }

    try {
      if (!results.hasMore()) {
        logger.info("In validateLDAP No search result came ");
        throw new UnauthorizedException(principal, actions, entityId);
      }
    } finally {
      results.close();
    }
    // Currently assumes membership in a namespace allows full access, hence not checking actions

  }


  /**
   * TCS added method
   *
   * @param groupNamingEnum
   * @return
   */
  private List<String> getGroupList(NamingEnumeration<?> groupNamingEnum) throws Exception {
    List<String> groupList = new ArrayList<String>();
    try {
      while (groupNamingEnum.hasMoreElements()) {
        String str = (String) groupNamingEnum.next();
        groupList.add(str);
      }
    } catch (NamingException e) {
      LOG.error("NamingException occured : ", e);
      throw e;
    } catch (Exception e) {
      LOG.error("Exception occured : ", e);
      throw e;
    }
    return groupList;
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    Set<Privilege> privileges = new LinkedHashSet<>();
    if (handler == null) {
      handler = new FileHandler("/tmp/auth.log", true);
      logger = java.util.logging.Logger.getLogger("io.cdap.cdap.security.authorization.ldap");
      logger.addHandler(handler);
    }
    logger.info("In list Privilages for principal:" + principal.getName());
    String filter = "(&(objectClass={0})({1}={2}))";
    int i = 1;
    // Query for all instances and namespaces that the given principal is a member of
    for (SearchConfig searchConfig : Arrays.asList(instanceSearchConfig, namespaceSearchConfig)) {
      Object[] filterArgs = new Object[]{
        searchConfig.getObjectClass(), searchConfig.getMemberAttribute(),
        String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
      };
      SearchControls searchControls = new SearchControls();
      searchControls.setDerefLinkFlag(true);
      searchControls.setReturningAttributes(new String[]{searchConfig.getNameAttribute()});
      if (searchRecursive) {
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      }
      NamingEnumeration<SearchResult> results = null;
      try {

        logger.info("In listPrivileges before original code of dir contect search ");
        logger.info("In listPrivileges, search configbasedn: " + searchConfig.getBaseDn() + " ,filter:" + filter);
        for (Object obj : filterArgs) {
          logger.info("In listPrivileges, filter args: " + obj.toString());
        }
        results = dirContext.search(searchConfig.getBaseDn(),
                                    filter, filterArgs, searchControls);

        // When a user is in a given group, then he is allowed to perform all action in that group
        while (results.hasMore()) {
          SearchResult result = results.next();
          Attribute attribute = result.getAttributes().get(searchConfig.getNameAttribute());
          if (attribute != null) {
            String entityName = attribute.get().toString();
            logger.info("Privilages added to list: " + entityName);
            for (Action action : Action.values()) {
              logger.info("Action value: " + action.toString());
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

	/*
  @Override
  public void grant(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("grant not support");
  }

  @Override
  public void revoke(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("revoke not support");
  }

  @Override
  public void revoke(EntityId entityId) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("revoke not support");
  }
	 */


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
    if (handler == null) {
      handler = new FileHandler("/tmp/auth.log", true);
      logger = java.util.logging.Logger.getLogger("io.cdap.cdap.security.authorization.ldap");
      logger.addHandler(handler);
    }
    logger.info("In create Search config for keyPrefix:" + keyPrefix
                  + "baseDn:" + baseDn + "ObjectClass:" + objectClass
                  + "memberAttribute:" + memberAttribute + "nameAttribute:" + nameAttribute);
    return new SearchConfig(baseDn, objectClass, memberAttribute, nameAttribute, adminValue);
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

  @Override
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {

    logger.info("Inside Is Visible " + entityIds);

    Set<EntityId> visibleEntities = new HashSet<>(entityIds.size());
    Set<Action> validateAction = new HashSet<>(1);
    validateAction.add(Action.ADMIN);
    for (EntityId entityId : entityIds) {
      try {
        validateLDAP(entityId, principal, validateAction);
        logger.info("Entity " + entityId + "is  visible for principal." + principal);
        visibleEntities.add(entityId);
      } catch (Exception ex) {
        logger.info("Entity " + entityId + "is not visible for principal." + principal);
      }
    }
    return visibleEntities;
  }
}
