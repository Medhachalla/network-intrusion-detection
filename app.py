import streamlit as st
import pandas as pd
import joblib
import plotly.express as px

# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="",
    layout="wide"
)

# ==================================================
# LOAD TRAINED ARTIFACTS
# ==================================================

model = joblib.load("models/logistic_regression_model.pkl")
scaler = joblib.load("models/scaler.pkl")
label_encoder = joblib.load("models/label_encoder.pkl")
feature_columns = joblib.load("models/feature_columns.pkl")

# ==================================================
# ORIGINAL NSL KDD COLUMN NAMES
# ==================================================

column_names = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "attack",
    "difficulty"
]

# ==================================================
# HELPER FUNCTIONS
# ==================================================

def preprocess(df):

    df = pd.get_dummies(
        df,
        columns=[
            "protocol_type",
            "service",
            "flag"
        ]
    )

    df = df.reindex(
        columns=feature_columns,
        fill_value=0
    )

    return df


def severity(prediction):

    if prediction == "U2R":
        return "Critical"

    elif prediction == "R2L":
        return "High"

    elif prediction == "DoS":
        return "Medium"

    elif prediction == "Probe":
        return "Low"

    return "Safe"


# ==================================================
# HEADER
# ==================================================

st.title("Network Intrusion Detection System")

st.markdown(
    """
Detect cyber attacks using a machine learning model trained on the NSL KDD dataset.
"""
)

# ==================================================
# FILE UPLOAD
# ==================================================

uploaded_file = st.file_uploader(
    "Upload KDDTest+.txt",
    type=["txt"]
)

# ==================================================
# MAIN LOGIC
# ==================================================

if uploaded_file is not None:

    # Load TXT file
    df = pd.read_csv(
        uploaded_file,
        header=None
    )

    # Assign proper column names
    df.columns = column_names

    # Keep original for display
    display_df = df.copy()

    # Drop columns not used for training
    df = df.drop(
        columns=[
            "attack",
            "difficulty"
        ]
    )

    st.subheader("Dataset Preview")

    st.dataframe(display_df.head())

    st.write(
        f"Rows: {display_df.shape[0]} | Columns: {display_df.shape[1]}"
    )

    # ==================================================
    # PREPROCESS
    # ==================================================

    processed_df = preprocess(df)

    scaled_data = scaler.transform(
        processed_df
    )

    # ==================================================
    # PREDICTIONS
    # ==================================================

    predictions = model.predict(
        scaled_data
    )

    predictions = label_encoder.inverse_transform(
        predictions
    )

    display_df["Prediction"] = predictions

    display_df["Severity"] = (
        display_df["Prediction"]
        .apply(severity)
    )

    # ==================================================
    # SUMMARY METRICS
    # ==================================================

    total_connections = len(display_df)

    attack_connections = len(
        display_df[
            display_df["Prediction"] != "Normal"
        ]
    )

    normal_connections = len(
        display_df[
            display_df["Prediction"] == "Normal"
        ]
    )

    attack_percentage = round(
        attack_connections / total_connections * 100,
        2
    )

    st.subheader("Security Summary")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Connections",
        total_connections
    )

    col2.metric(
        "Attack Connections",
        attack_connections
    )

    col3.metric(
        "Normal Connections",
        normal_connections
    )

    col4.metric(
        "Attack %",
        f"{attack_percentage}%"
    )

    # ==================================================
    # ATTACK DISTRIBUTION
    # ==================================================

    st.subheader("Attack Distribution")

    fig = px.pie(
        display_df,
        names="Prediction",
        title="Predicted Attack Categories"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # ==================================================
    # SEVERITY DISTRIBUTION
    # ==================================================

    st.subheader("Threat Severity Distribution")

    severity_counts = (
        display_df["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]

    fig2 = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        title="Threat Severity Counts"
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )

    # ==================================================
    # PREDICTIONS TABLE
    # ==================================================

    st.subheader("Prediction Results")

    st.dataframe(
        display_df[
            [
                "protocol_type",
                "service",
                "flag",
                "Prediction",
                "Severity"
            ]
        ]
    )

    # ==================================================
    # INCIDENT REPORT
    # ==================================================

    most_common_threat = (
        display_df["Prediction"]
        .value_counts()
        .idxmax()
    )

    report = f"""
NETWORK SECURITY REPORT

Total Connections: {total_connections}

Attack Connections: {attack_connections}

Normal Connections: {normal_connections}

Attack Percentage: {attack_percentage}%

Most Common Threat: {most_common_threat}

Threat Breakdown:

{display_df['Prediction'].value_counts().to_string()}
"""

    st.subheader("Incident Report")

    st.text(report)

    # ==================================================
    # DOWNLOAD REPORT
    # ==================================================

    st.download_button(
        label="📄 Download Security Report",
        data=report,
        file_name="security_report.txt",
        mime="text/plain"
    )