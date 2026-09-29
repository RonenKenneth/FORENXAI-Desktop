# Scope and claim boundary

## What this model was built from

Trained and validated entirely on TRUSTLab. 951,944 training flows, 167,993
held out for early stopping and 280,063 held-out test flows, sixteen
classes, random split. Test accuracy 0.9313, macro F1 0.9267.

## Where it has been shown to work

TRUSTLab held-out data only -- the same capture environment it learned from.

## Where it has not

Everywhere else. This is measured, not cautious wording. The same project
trained fifteen binary detectors on CICIDS2018 and TII-SSRC-23 and tested
them on TRUSTLab: mean ROC-AUC 0.4698, with ten of fifteen below 0.50 --
worse than a coin flip, despite scoring 0.839-0.999 on their own data.

The cause was diagnosed: flow features do not survive a change of capture
environment. Training flows were extracted with a 120-second timeout;
TRUSTLab flows run to 15,717 seconds. Seventeen of the 66 features differ
by more than three standard deviations between the two, and twenty-five do
for the CICIDS2018-only detector.

## What to say in an interface

> Trained and validated on TRUSTLab. Accuracy on other capture environments
> is not established.

## What deploying elsewhere would require

Labelled traffic from the target network, extracted with a documented and
matching flow-timeout configuration, and retraining. Not a configuration
change.

## Per-class reliability

Twelve of sixteen classes are at F1 0.94 or above. Four are not:

| Class | F1 | Note |
|---|---|---|
| DoS | 0.6714 | confused with Slowloris |
| Slowloris | 0.7639 | confused with DoS |
| Exploitation | 0.7838 | bleeds into BufferOverflow |
| BufferOverflow | 0.8017 | overlaps Exploitation |
