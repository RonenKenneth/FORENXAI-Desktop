# How far a SHAP attribution can be pushed

Quote these limits alongside any explanation. They are what separates an
explanation from a claim.

## What a SHAP value is

The contribution one feature made to this prediction, relative to the average
prediction across the background data. Contributions sum to the prediction.
The algorithm here is exact TreeSHAP (Lundberg et al. 2020), not an
approximation.

## What it is not

**Not causation.** "Flow Duration drove this prediction" means the model
weighted that feature heavily. It does not mean long duration causes the
attack, or that shortening it would prevent one.

**Not an absolute.** Attribution is measured against a baseline -- the mean
prediction -- not against zero. A feature with attribution near zero was not
necessarily irrelevant; it may simply have been near its typical value.

**Not stable under correlation.** Flow features are heavily inter-correlated
(packet length mean, max and std move together). Correlated features share
credit in ways that look arbitrary. A low attribution does not prove a
feature carries no information.

**Not a defence of a wrong answer.** SHAP explains the model, not the world.
A confident, coherent explanation of a misclassification is still a
misclassification.

## Specific to this model

Values are computed on **scaled** features. The raw value shown in the
interface is for human reading only; the model reasons in the scaled space.

Slowloris and DoS have a per-feature importance correlation of **0.9044**
and share six of their top ten features. When either is predicted with the
other close behind, the attribution will look similar for both -- because it
genuinely is. Report the ambiguity, do not resolve it.

The model was trained and validated on TRUSTLab. An explanation of a flow
from a different capture environment is an explanation of what the model
did, not evidence the model was right.
