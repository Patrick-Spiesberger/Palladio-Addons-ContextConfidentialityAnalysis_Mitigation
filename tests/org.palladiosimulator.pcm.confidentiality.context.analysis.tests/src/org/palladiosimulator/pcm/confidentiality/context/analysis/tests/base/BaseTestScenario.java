package org.palladiosimulator.pcm.confidentiality.context.analysis.tests.base;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.emf.ecore.resource.Resource;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.Configuration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.ScenarioAnalysis;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemcontextFactory;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.XACMLGenerator;
import org.palladiosimulator.pcm.repository.Repository;
import org.palladiosimulator.pcm.system.System;
import org.palladiosimulator.pcm.usagemodel.UsageModel;

public abstract class BaseTestScenario extends BaseTest {

    private static final String PATH_ASSEMBLY = "travelplanner/default.system";
    private static final String PATH_REPOSITORY = "travelplanner/default.repository";
    private static final String PATH_USAGE = "travelplanner/default.usagemodel";
    private static final String PATH_CONTEXT = "travelplanner/Scenarios/test_scenarios.context";
    protected Repository repo;
    protected UsageModel usage;
    protected System assembly;
    protected ConfidentialAccessSpecification context;
    protected PCMBlackBoard blackBoard;
    protected ScenarioAnalysis analysis;
    protected Configuration configuration;

    @Override
    protected List<String> getModelsPath() {
        final var list = new ArrayList<String>();

        list.add(PATH_USAGE);
        list.add(PATH_ASSEMBLY);
        list.add(PATH_REPOSITORY);
        list.add(PATH_CONTEXT);

        return list;
    }

    //    protected abstract void initLocal();

    @Override
    protected void assignValues(final List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.repo = this.getModel(list, Repository.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.usage = this.getModel(list, UsageModel.class);
    }

    @Override
    protected void generateXML() {
        var generator = new XACMLGenerator();
        var blackboard = new org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard(
                this.assembly, null, null);
        generator.generateXACML(blackboard, this.context, this.pathXACML);
    }

    //    protected ContextAttribute getContextAttributeByName(final String name) {
    //        final var contextAttribute = this.context.getAttributes()
    //
    //
    //                getContextContainer().stream().flatMap(e -> e.getContext().stream())
    //                .filter(e -> name.equals(e.getEntityName())).findAny();
    //        if (contextAttribute.isEmpty()) {
    //            fail("ContextAttribute with name " + name + " not found");
    //        }
    //        return contextAttribute.get();
    //    }
    //
    //    protected ContextSpecification getSpecificationByName(final String name) {
    //        final var specification = this.context.getPcmspecificationcontainer().getContextspecification().stream()
    //                .filter(e -> name.equals(e.getEntityName())).findAny();
    //        if (specification.isEmpty()) {
    //            fail("Specification with name " + name + " not found");
    //        }
    //        return specification.get();
    //    }
    //
    //    protected SystemPolicySpecification getPolicySpecificationByName(final String name) {
    //        final var policySpecification = this.context.getPcmspecificationcontainer().getPolicyspecification().stream()
    //                .filter(e -> name.equals(e.getEntityName())).findAny();
    //        if (policySpecification.isEmpty()) {
    //            fail("Policy with name " + name + " not found");
    //        }
    //        return policySpecification.get();
    //    }
    //
    //    protected DecisionType getScenarioResultByName(final AnalysisResults results, final String name) {
    //        final var scenario = getScenarioByName(results, name);
    //        return scenario.getDecision();
    //    }
    //
    //    protected List<ScenarioOutput> getScenariosByName(final AnalysisResults results, final String name) {
    //        return results.getScenariooutput().stream().filter(e -> e.getScenario().getEntityName().equals(name))
    //                .collect(Collectors.toList());
    //    }
    //
    //    protected ScenarioOutput getScenarioByName(final AnalysisResults results, final String name) {
    //        final var output = results.getScenariooutput().stream()
    //                .filter(e -> e.getScenario().getEntityName().equals(name)).findAny();
    //        if (output.isEmpty()) {
    //            fail("Scenario with name " + name + " not found");
    //        }
    //        return output.get();
    //    }
    //
    //    protected void clearContextSetByName(final String name) {
    //        final var set = getPolicyByName(name);
    //        set.getRule().clear();
    //    }
    //
    //    protected Policy getPolicyByName(final String name) {
    //        final var set = this.context.getPolicyset().getPolicy().stream().filter(e -> name.equals(e.getEntityName()))
    //                .findAny();
    //        if (set.isEmpty()) {
    //            fail("Contextset with name " + name + " not found");
    //        }
    //        return set.get();
    //    }
    //
    //    protected ContextAttribute createSingleContext(final String name) {
    //        final var context = ModelFactory.eINSTANCE.createSingleAttributeContext();
    //        context.setEntityName(name);
    //        return context;
    //    }
    //
    //    protected HierarchicalContext createHierarchicalContext(final String name) {
    //        final var context = ModelFactory.eINSTANCE.createHierarchicalContext();
    //        context.setEntityName(name);
    //        return context;
    //    }
    //
    //    protected RelatedContextSet createRelatedContext(final String name) {
    //        final var context = ModelFactory.eINSTANCE.createRelatedContextSet();
    //        context.setEntityName(name);
    //        return context;
    //
    //    }

    protected UsageSpecification createContext(final String name) {
        final var contextAccess = SystemFactory.eINSTANCE.createUsageSpecification();

        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        var attributeValue = SystemcontextFactory.eINSTANCE.createAttributeValue();
        attributeValue.getValues().add(name);
        attributeValue.setType(DataTypes.STRING);
        attribute.getAttributevalue().add(attributeValue);

        contextAccess.setEntityName(name);
        contextAccess.setAttribute(attribute);
        contextAccess.setAttributevalue(attributeValue);
        this.context.getAttributes().getAttribute().add(attribute);
        this.context.getPcmspecificationcontainer().getUsagespecification().add(contextAccess);
        return contextAccess;
    }

}
