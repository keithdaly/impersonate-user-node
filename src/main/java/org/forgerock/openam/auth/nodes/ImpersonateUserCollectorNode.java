/*
 * Copyright 2017-2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

        import static org.forgerock.openam.auth.node.api.Action.send;

        import java.util.ResourceBundle;

        import javax.security.auth.callback.NameCallback;

        //import org.forgerock.guava.common.base.Strings;
        import com.google.common.base.Strings;
        import org.forgerock.json.JsonValue;
        import org.forgerock.openam.auth.node.api.Action;
        import org.forgerock.openam.auth.node.api.Node;
        import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
        import org.forgerock.openam.auth.node.api.TreeContext;
        import org.slf4j.Logger;
        import org.slf4j.LoggerFactory;

/**
 * A node which collects a username from the user via a name callback.
 *
 * <p>Places the result in the shared state as 'impersonateUsername'.</p>
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = ImpersonateUserCollectorNode.Config.class)
public class ImpersonateUserCollectorNode extends SingleOutcomeNode {

    private String IMPERSONATE_USERNAME = "impersonateUsername";

    /**
     * Configuration for the username collector node.
     */
    public interface Config {
    }

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ImpersonateUserCollectorNode";
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    //private final Logger logger = LoggerFactory.getLogger(ImpersonateUserNode.class);

    @Override
    public Action process(TreeContext context) {
        logger.debug("ImpersonateUserCollectorNode started");
        JsonValue sharedState = context.sharedState;
        return context.getCallback(NameCallback.class)
                .map(NameCallback::getName)
                .filter(password -> !Strings.isNullOrEmpty(password))
                .map(impersonateName -> goToNext().replaceSharedState(sharedState.copy().put(IMPERSONATE_USERNAME, impersonateName)).build())
                .orElseGet(() -> collectImpersonateUsername(context));
    }

    private Action collectImpersonateUsername(TreeContext context) {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        logger.debug("collecting impersonateUsername");
        return send(new NameCallback(bundle.getString("callback.impersonateUsername"))).build();
    }
}
