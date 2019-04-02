/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Iterator;

import javax.inject.Inject;

import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.json.JsonValue;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = ImpersonateUserNode.Config.class)
public class ImpersonateUserNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(ImpersonateUserNode.class);
    private final Config config;
    private final Realm realm;
    private final CoreWrapper coreWrapper;

    private String username;
    private String impersonateUsername;
    private AMIdentity userIdentity;

//    protected Debug debug = Debug.getInstance("ImpersonateUserNode");

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The group name (or fully-qualified unique identifier) for the group that the identity must be in.
         */
        @Attribute(order = 100)
        default String groupName() {
            return "impersonate";
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ImpersonateUserNode(CoreWrapper coreWrapper, @Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        username = context.sharedState.get("username").asString();
        impersonateUsername = context.sharedState.get("impersonateUsername").asString();

        userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(), context.sharedState.get(REALM).asString());
        AMIdentity userIdentity = IdUtils.getIdentity(username, realm.asDN());
        AMIdentity impersonateUserIdentity = IdUtils.getIdentity(impersonateUsername, realm.asDN());
        try {
            if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()
                    && isMemberOfGroup(userIdentity, config.groupName())) {
                if (impersonateUserIdentity != null && impersonateUserIdentity.isExists() && impersonateUserIdentity.isActive()) {
                    return goTo(true)
                            .replaceSharedState(context.sharedState.copy().put(USERNAME, impersonateUsername))
                            .replaceTransientState(context.transientState.copy())
                            .build();
                }
            }
        } catch (IdRepoException | SSOException e) {
            logger.warn("Error locating user '{}' or '{}'", username, impersonateUsername, e);
        }
        return goTo(false).build();
    }

    @Override
    public JsonValue getAuditEntryDetail() {
        return json(object(field("Impersonation",
                username + " impersonating " + impersonateUsername)));
    }

    private boolean isMemberOfGroup(AMIdentity userIdentity, String groupName) {
        try {
            Set userGroups = userIdentity.getMemberships(IdType.GROUP);
            Iterator i = userGroups.iterator();
            while(i.hasNext()) {
                if (groupName.equals(((AMIdentity)i.next()).getName())) {
                    return true;
                }
            }
        } catch (IdRepoException | SSOException e) {
            logger.warn("Could not load groups for user {}", userIdentity);
        }
        return false;
    }
}
