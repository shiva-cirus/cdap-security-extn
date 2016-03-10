/*
 * Copyright 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.provider.common.AuthorizationProvider;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * This class instantiate the {@link AuthorizationProvider} configured in {@link AuthConf} and is responsible for
 * performing different authorization operation on it.
 */
class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  //TODO: This should not be here. Change this when SENTRY-1119 is fixed and merged
  private static final String COMPONENT_TYPE = "cdap";
  private final AuthConf authConf;
  private final AuthorizationProvider authProvider;
  private final String instanceName;
  private final String requestorName;
  private final ActionFactory actionFactory;

  public AuthBinding(String sentrySite, String instanceName, String requestorName) {
    this.authConf = initAuthzConf(sentrySite);
    this.instanceName = instanceName;
    //TODO: When we start working with Kerberos requestorName should be the the user logged in cdap.
    this.requestorName = requestorName;
    this.authProvider = createAuthProvider();
    actionFactory = new ActionFactory();
  }

  private AuthConf initAuthzConf(String sentrySite) {
    if (Strings.isNullOrEmpty(sentrySite)) {
      throw new IllegalArgumentException(String.format("The value for %s is null or empty. Please configure it to " +
                                                         "the path of sentry-site.xml in cdap-site.xml",
                                                       AuthConf.SENTRY_SITE_URL));
    }
    AuthConf authConf;
    try {
      authConf = new AuthConf(new URL(sentrySite));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(String.format("The path provided for sentry-site.xml in property %s is " +
                                                         "invalid.", AuthConf.SENTRY_SITE_URL), e);
    }
    return authConf;
  }

  /**
   * Instantiate the configured {@link AuthorizationProvider}
   *
   * @return {@link AuthorizationProvider} configured in {@link AuthConf}
   */
  private AuthorizationProvider createAuthProvider() {

    String authProviderName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER.getVar(),
                                           AuthzConfVars.AUTHZ_PROVIDER.getDefault());

    String providerBackendName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getVar(),
                                              AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getDefault());

    String policyEngineName = authConf.get(AuthzConfVars.AUTHZ_POLICY_ENGINE.getVar(),
                                           AuthzConfVars.AUTHZ_POLICY_ENGINE.getDefault());

    String resourceName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getVar(),
                                       AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getDefault());
    if (resourceName != null && resourceName.startsWith("classpath:")) {
      String resourceFileName = resourceName.substring("classpath:".length());
      resourceName = getClass().getClassLoader().getResource(resourceFileName).getPath();
    }

    LOG.debug("Trying to instantiate authorization provider {}, with provider backend {} and policy engine {}",
              authProviderName, providerBackendName, policyEngineName);

    // Instantiate the configured providerBackend
    try {
      // get the current context classloader
      ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

      // instantiate the configured provider backend
      Constructor<?> providerBackendConstructor = classLoader.loadClass(providerBackendName)
        .getDeclaredConstructor(Configuration.class, String.class);
      providerBackendConstructor.setAccessible(true);
      ProviderBackend providerBackend = (ProviderBackend) providerBackendConstructor.newInstance(authConf,
                                                                                                 resourceName);
      if (providerBackend instanceof SentryGenericProviderBackend) {
        ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_TYPE);
        ((SentryGenericProviderBackend) providerBackend).setServiceName(instanceName);
      }

      // instantiate the configured policy engine
      Constructor<?> policyConstructor = classLoader.loadClass(policyEngineName)
        .getDeclaredConstructor(ProviderBackend.class);
      policyConstructor.setAccessible(true);
      PolicyEngine policyEngine = (PolicyEngine) policyConstructor.newInstance(providerBackend);

      // Instantiate the configured authz provder
      Constructor<?> constructor =
        classLoader.loadClass(authProviderName).getDeclaredConstructor(Configuration.class, String.class,
                                                                       PolicyEngine.class);
      constructor.setAccessible(true);
      return (AuthorizationProvider) constructor.newInstance(authConf, resourceName, policyEngine);
    } catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  /**
   * Grants the given {@link Set} of {@link Action} on the given {@link EntityId} to the given {@link Principal}
   *
   * @param entityId on which the actions need to be granted
   * @param principal to whom the actions needs to granted
   * @param actions the actions which needs to be granted
   */
  public void grant(final EntityId entityId, Principal principal, Set<Action> actions) {
    Preconditions.checkArgument(principal.getType() == Principal.PrincipalType.ROLE, "The given principal {} is of " +
      "type {}. In Sentry grants can only be done on roles. Please add the {}:{} to a role and perform grant on the " +
      "role.", principal, principal.getType(), principal.getType(), principal.getName());
    final String role = principal.getName();
    if (!roleExists(role)) {
      throw new IllegalArgumentException(String.format("Failed to perform grant. Role %s does not exists.", role));
    }
    LOG.info("Granting actions {} on entity {} from principal {} on request of {}", actions, entityId, principal,
             requestorName);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.grantPrivilege(requestorName, role, COMPONENT_TYPE, toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  public void revoke(final EntityId entityId, Principal principal, Set<Action> actions) {
    Preconditions.checkArgument(principal.getType() == Principal.PrincipalType.ROLE, "The given principal {} is of " +
                                  "type {}. In Sentry revoke can only be done on roles.", principal,
                                principal.getType(), principal.getType(), principal.getName());
    final String role = principal.getName();
    if (!roleExists(role)) {
      throw new IllegalArgumentException(String.format("Failed to perform revoke. Role %s does not exists.", role));
    }
    LOG.info("Revoking actions {} on entity {} from principal {} on request of {}", actions, entityId, principal,
             requestorName);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.dropPrivilege(requestorName, role, toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  public void revoke(EntityId entityId) {
    List<String> allRoles = getAllRoles();
    final List<TSentryPrivilege> allPrivileges = getAllPrivileges(allRoles);
    final List<TAuthorizable> tAuthorizables = toTAuthorizable(entityId);
    LOG.info("Revoking all actions for all users from entity {} on request of {}", entityId, requestorName);
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (TSentryPrivilege curPrivileges : allPrivileges) {
          if (tAuthorizables.equals(curPrivileges.getAuthorizables())) {
            // if the privilege is on same authorizables then drop it
            client.dropPrivilege(requestorName, COMPONENT_TYPE, curPrivileges);
          }
        }
        return null;
      }
    });
  }

  private List<TSentryPrivilege> getAllPrivileges(final List<String> roles) {
    final List<TSentryPrivilege> tSentryPrivileges = new ArrayList<>();
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (String role : roles) {
          tSentryPrivileges.addAll(client.listPrivilegesByRoleName(requestorName, role, COMPONENT_TYPE, instanceName));
        }
        return null;
      }
    });
    return tSentryPrivileges;
  }

  /**
   * Check if the given {@link Principal} is allowed to perfom the given {@link Action} on the {@link EntityId}
   *
   * @param entityId {@link EntityId} of the entity on which the action is being performed
   * @param principal the {@link Principal} who needs to perform this action
   * @param action {@link Action} the action which needs to be checked
   * @return true if the given {@link Principal} can perform the given {@link Action} on the given {@link EntityId}
   * else false
   */
  public boolean authorize(EntityId entityId, Principal principal, Action action) {
    List<Authorizable> authorizables = EntityToAuthMapper.convertEntityToAuthorizable(instanceName, entityId);
    Set<ActionFactory.Action> actions = Sets.newHashSet(actionFactory.getActionByName(action.name()));
    return authProvider.hasAccess(new Subject(principal.getName()), authorizables, actions, ActiveRoleSet.ALL);
  }

  private boolean roleExists(String role) {
    return getAllRoles().contains(role);
  }

  private List<String> getAllRoles() {
    final List<String> roles = new ArrayList<>();
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (TSentryRole tSentryRole : client.listAllRoles(requestorName, COMPONENT_TYPE)) {
          roles.add(tSentryRole.getRoleName());
        }
        return null;
      }
    });
    return roles;
  }

  private TSentryPrivilege toTSentryPrivilege(EntityId entityId, Action action) {
    List<Authorizable> authorizables = EntityToAuthMapper.convertEntityToAuthorizable(instanceName, entityId);
    List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (Authorizable authorizable : authorizables) {
      tAuthorizables.add(new TAuthorizable(authorizable.getTypeName(), authorizable.getName()));
    }
    return new TSentryPrivilege(COMPONENT_TYPE, instanceName, tAuthorizables, action.name());
  }

  private List<TAuthorizable> toTAuthorizable(EntityId entityId) {
    return toTSentryPrivilege(entityId, Action.ALL).getAuthorizables();
  }

  private <T> T execute(Command<T> cmd) throws RuntimeException {
    SentryGenericServiceClient client = null;
    try {
      client = getClient();
      return cmd.run(client);
    } catch (Exception ex) {
      throw Throwables.propagate(ex);
    } finally {
      if (client != null) {
        client.close();
      }
    }
  }

  /**
   * A Command is a closure used to pass a block of code from individual functions to execute, which centralizes
   * connection error handling. Command is parameterized on the return type of the function.
   */
  private interface Command<T> {
    T run(SentryGenericServiceClient client) throws Exception;
  }

  private SentryGenericServiceClient getClient() throws Exception {
    return SentryGenericServiceClientFactory.create(this.authConf);
  }
}
