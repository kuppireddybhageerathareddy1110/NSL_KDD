import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# =====================================
# 1. LOAD NSL-KDD DATASET
# =====================================
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

data = pd.read_csv("NSL_KDD.csv", header=None, names=columns, low_memory=False)
data.drop(columns=['difficulty'], inplace=True)

print("Dataset Shape:", data.shape)

# =====================================
# 2. ATTACK CATEGORY MAPPING
# =====================================
dos = [
    'back','land','neptune','pod','smurf','teardrop',
    'mailbomb','apache2','processtable','udpstorm'
]

probe = [
    'ipsweep','nmap','portsweep','satan','mscan','saint'
]

r2l = [
    'ftp_write','guess_passwd','imap','multihop',
    'phf','spy','warezclient','warezmaster'
]

u2r = [
    'buffer_overflow','loadmodule','perl','rootkit'
]

def map_attack(label):
    if label == 'normal':
        return 'Normal'
    elif label in dos:
        return 'DoS'
    elif label in probe:
        return 'Probe'
    elif label in r2l:
        return 'R2L'
    elif label in u2r:
        return 'U2R'
    else:
        return 'Other'

data['attack_class'] = data['label'].apply(map_attack)

print("\nAttack Class Distribution:")
print(data['attack_class'].value_counts())

# =====================================
# 3. ENCODE CATEGORICAL FEATURES
# =====================================
encoder = LabelEncoder()

categorical_cols = ['protocol_type', 'service', 'flag']
for col in categorical_cols:
    data[col] = encoder.fit_transform(data[col])

# Encode target labels
target_encoder = LabelEncoder()
data['attack_class'] = target_encoder.fit_transform(data['attack_class'])

# =====================================
# 4. NUMERIC CONVERSION + CLEANING
# =====================================
for col in data.columns:
    if col not in ['label', 'attack_class']:
        data[col] = pd.to_numeric(data[col], errors='coerce')

data.fillna(0, inplace=True)

# =====================================
# 5. FEATURE / TARGET SPLIT
# =====================================
X = data.drop(columns=['label', 'attack_class'])
y = data['attack_class']

# =====================================
# 6. TRAIN-TEST SPLIT
# =====================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# =====================================
# 7. FEATURE SCALING
# =====================================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# =====================================
# 8. TRAIN RANDOM FOREST (MULTI-CLASS)
# =====================================
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# =====================================
# 9. EVALUATION
# =====================================
y_pred = model.predict(X_test)

print("\nModel Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=target_encoder.classes_,
    zero_division=0
))

# =====================================
# 10. CONFUSION MATRIX
# =====================================
cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(7,6))
sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues',
    xticklabels=target_encoder.classes_,
    yticklabels=target_encoder.classes_
)
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Multi-Class IDS Confusion Matrix")
plt.show()

# =====================================
# 11. FEATURE IMPORTANCE
# =====================================
feature_importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

print("\nTop 10 Important Features:")
print(feature_importance.head(10))

# =====================================
# 12. SAVE MODEL
# =====================================
joblib.dump(model, "ids_multiclass_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(target_encoder, "label_encoder.pkl")

# =====================================
# 13. SINGLE SAMPLE PREDICTION
# =====================================
sample = pd.DataFrame([X.iloc[0]], columns=X.columns)
sample_scaled = scaler.transform(sample)
pred = model.predict(sample_scaled)

print(
    "\nSample Prediction:",
    target_encoder.inverse_transform(pred)[0]
)
