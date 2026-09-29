"""
Model architectures for binary flow classification.

FOUR DEEP ARCHITECTURES PLUS ONE CONTROL

The deep set follows Hossain (2025), who compared 1D CNN, LSTM, RNN and MLP
on CIC IoT-DIAD 2024 and found the 1D CNN best. Two deliberate changes:

  * Plain RNN is replaced by CNN-BiLSTM. Simple RNNs suffer vanishing
    gradients and were Hossain's weakest model; they add little an LSTM does
    not already cover. A convolutional front-end feeding a bidirectional LSTM
    captures local feature interactions and longer-range structure together,
    which is the plausible advantage on low-and-slow attack families.

  * XGBoost is included as a non-deep control. TRUSTLab's published baseline
    used XGBoost for its multiclass stage, so this gives a directly comparable
    reference point. Without it there is no evidence that the deep models are
    actually better -- and if XGBoost wins, that is a finding worth reporting
    rather than a gap in the comparison.

AN ASSUMPTION WORTH STATING IN THE METHODOLOGY

Flow features are not a time series. Treating the N features as a sequence of
length N with one channel -- which is what CNN1D, LSTM and CNN-BiLSTM all do
here -- is the convention in this literature, but it is a modelling choice,
not a property of the data. Feature ordering is arbitrary. The MLP makes no
such assumption, which is partly why it belongs in the comparison.
"""
import sys
from pathlib import Path

import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import SEED, USE_GPU


def device():
    return torch.device("cuda" if (USE_GPU and torch.cuda.is_available())
                        else "cpu")


class MLP(nn.Module):
    """Dense feedforward. Treats features as an unordered vector."""

    def __init__(self, n_features, n_classes=2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, 256), nn.ReLU(), nn.BatchNorm1d(256),
            nn.Dropout(0.3),
            nn.Linear(256, 128), nn.ReLU(), nn.BatchNorm1d(128),
            nn.Dropout(0.3),
            nn.Linear(128, 64), nn.ReLU(),
            nn.Linear(64, n_classes),
        )

    def forward(self, x):
        return self.net(x)


class CNN1D(nn.Module):
    """
    1D convolution across the feature vector. Hossain's best-performing
    architecture. Input is reshaped to (batch, 1 channel, n_features).
    """

    def __init__(self, n_features, n_classes=2):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, 64, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(64),
            nn.MaxPool1d(2),
            nn.Conv1d(64, 128, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(128),
            nn.MaxPool1d(2),
            nn.Conv1d(128, 64, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(64),
            nn.AdaptiveAvgPool1d(1),
        )
        self.head = nn.Sequential(
            nn.Flatten(), nn.Dropout(0.3),
            nn.Linear(64, 64), nn.ReLU(),
            nn.Linear(64, n_classes),
        )

    def forward(self, x):
        return self.head(self.conv(x.unsqueeze(1)))


class LSTMNet(nn.Module):
    """Stacked LSTM reading the feature vector as a sequence."""

    def __init__(self, n_features, n_classes=2, hidden=128, layers=2):
        super().__init__()
        self.lstm = nn.LSTM(1, hidden, num_layers=layers,
                            batch_first=True, dropout=0.2)
        self.head = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(hidden, 64), nn.ReLU(),
            nn.Linear(64, n_classes),
        )

    def forward(self, x):
        out, _ = self.lstm(x.unsqueeze(-1))
        return self.head(out[:, -1, :])


class CNN_BiLSTM(nn.Module):
    """
    Convolutional front-end into a bidirectional LSTM. The convolution finds
    local feature interactions; the BiLSTM reads the result in both
    directions, so position in the feature vector matters less.
    """

    def __init__(self, n_features, n_classes=2, hidden=96):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, 64, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(64),
            nn.Conv1d(64, 64, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(64),
        )
        self.lstm = nn.LSTM(64, hidden, num_layers=1,
                            batch_first=True, bidirectional=True)
        self.head = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(hidden * 2, 64), nn.ReLU(),
            nn.Linear(64, n_classes),
        )

    def forward(self, x):
        z = self.conv(x.unsqueeze(1)).transpose(1, 2)
        out, _ = self.lstm(z)
        return self.head(out[:, -1, :])


BUILDERS = {
    "MLP": MLP,
    "CNN1D": CNN1D,
    "LSTM": LSTMNet,
    "CNN_BiLSTM": CNN_BiLSTM,
}


def build(name, n_features, n_classes=2):
    torch.manual_seed(SEED)
    if name not in BUILDERS:
        raise ValueError(f"Unknown model '{name}'. Available: {list(BUILDERS)}")
    return BUILDERS[name](n_features, n_classes).to(device())


def build_xgboost(scale_pos_weight=1.0):
    """
    Tree-based control. scale_pos_weight is XGBoost's class-imbalance
    correction -- the equivalent of the class weights used in the deep models,
    so the comparison stays fair.
    """
    import xgboost as xgb
    # USE_GPU is a request, not a fact. On a machine with no CUDA, asking
    # XGBoost for "cuda" makes it warn about the device mismatch on every fit
    # and predict and fall back to CPU -- and older builds raise instead, which
    # script 05 would catch as a model failure and drop the one non-deep
    # control from the comparison. device() already resolves the request
    # against what is actually installed, so ask for what we can get.
    kw = {"tree_method": "hist"}
    if device().type == "cuda":
        kw["device"] = "cuda"
    return xgb.XGBClassifier(
        n_estimators=300, learning_rate=0.08, max_depth=8,
        min_child_weight=10, subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss", random_state=SEED, n_jobs=-1, **kw)


def build_xgboost_multiclass(n_classes):
    """
    The sixteen-class control, shared by scripts 09 and 12.

    It lives here rather than inline in either script for a specific reason:
    09 trains this model on the full class distribution, and 12 trains it on
    only the flows a Phase-1 detector flagged. Those two runs are meant to
    differ in the data they see and in nothing else, so if their
    hyperparameters could drift apart the comparison between them would stop
    meaning anything.
    """
    import xgboost as xgb
    kw = {"tree_method": "hist"}
    if device().type == "cuda":
        kw["device"] = "cuda"
    return xgb.XGBClassifier(
        n_estimators=400, learning_rate=0.08, max_depth=10,
        min_child_weight=5, subsample=0.8, colsample_bytree=0.8,
        objective="multi:softprob", num_class=n_classes,
        eval_metric="mlogloss", random_state=SEED, n_jobs=-1, **kw)


def count_parameters(model):
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def free_gpu():
    """Release cached GPU memory back to the driver.

    PyTorch never returns a block once it has allocated it -- the caching
    allocator holds it for reuse, which is the right trade inside torch and
    the wrong one the moment another library wants the same card. XGBoost
    asking for CUDA memory after four deep models have trained in this
    process finds nothing free, warns that its data is on the CPU while it
    is running on cuda:0, and falls back to a path that is an order of
    magnitude slower.

    Calling this before handing the GPU to a non-torch library costs a few
    milliseconds and nothing else: the models are already trained and saved,
    and the cache refills on the next allocation. It changes no result --
    the fits either side of this fix were byte-identical -- only the time
    they take.
    """
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        torch.cuda.empty_cache()
