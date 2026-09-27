"""
The model must see features scaled the way training scaled them:
cast to float32, then the bundle scaler (pipeline src/common.py,
clean_features). Scaling in float64 instead changed 3,004 of 280,063
TRUSTLab test predictions.

Run: .venv\\Scripts\\python.exe test_model_preprocessing.py
"""

import numpy as np
import pandas as pd

from app.services.model_service import load_model_bundle, prepare_model_input

bundle = load_model_bundle()
features = list(bundle["features"])

# Values that float32 cannot hold exactly, so float32 and float64
# scaling give different results.
row = {name: 123456789.123 for name in features}
frame = pd.DataFrame([row, {name: 0.1 for name in features}])

_, scaled = prepare_model_input(frame)

expected = bundle["scaler"].transform(frame[features].to_numpy(dtype=np.float32))
as_float64 = bundle["scaler"].transform(frame[features].to_numpy(dtype=np.float64))

assert np.array_equal(scaled, np.asarray(expected, dtype=np.float64)), "model input not scaled from float32"
assert not np.array_equal(expected, as_float64), "test values do not separate float32 from float64"
print("ALL CHECKS PASSED")
