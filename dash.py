import pandas as pd
from sqlalchemy import create_engine, text
from flask import Flask, render_template, jsonify, request 
from datetime import date, timedelta 
import os 
from typing import Dict, Any, List
from flask_cors import CORS

# ----------------- Database and Configuration -----------------
# NOTE: Using the provided database configuration. Ensure the database 
# is reachable and credentials are correct.
db_config = {
    'host': '34.93.75.171',
    'port': 3306,
    'user': 'appsadmin',
    'password': 'appsadmin2025',
    'database': 'timesheet'
}

engine = create_engine(
    f"mysql+pymysql://{db_config['user']}:{db_config['password']}@"
    f"{db_config['host']}:{db_config['port']}/{db_config['database']}"
)

# ----------------- Helper Function -----------------
def seconds_to_hhmmss(total_seconds: float | int | None) -> str:
    """மொத்த விநாடிகளை HH:MM:SS வடிவத்திற்கு மாற்றுகிறது. (Converts total seconds into HH:MM:SS format.)"""
    if total_seconds is None:
        return "00:00:00"
    s = int(round(total_seconds))
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    return f"{h:02d}:{m:02d}:{sec:02d}"

# ----------------- Data Loading and Processing (Dynamic) -----------------
# IMPORTANT: Added 'project_type' to the filter keys
FILTER_KEYS: List[str] = ['project', 'process', 'team', 'sub_process', 'name', 'project_type'] 

def fetch_and_process_data_from_db(start_date: str, end_date: str) -> Dict[str, Any]:
    """
    தரவுத்தளத்திலிருந்து ஒரு குறிப்பிட்ட காலவரம்புக்குரிய தரவை மீட்டெடுத்து,
    அதை டேஷ்போர்டுக்காக தயார் செய்கிறது.
    (Fetches data from DB based on a date range, processes it, and prepares it 
    for the dashboard.)
    """
    # SQL Query now includes the requested 'project_type_mc' column
    query = f"""
    SELECT
        id,
        name,
        team,
        `date`,
        project,
        process,
        sub_process,
        project_type_mc, -- The actual column requested by the user
        start_time,
        end_time,
        TIMESTAMPDIFF(
            SECOND,
            CONCAT(`date`, ' ', start_time),
            IF(end_time >= start_time,
                CONCAT(`date`, ' ', end_time),
                DATE_ADD(CONCAT(`date`, ' ', end_time), INTERVAL 1 DAY)
            )
        ) AS duration_seconds
    FROM timesheet.timesheetlogs
    WHERE `date` BETWEEN '{start_date}' AND '{end_date}'
    ORDER BY `date`, name, id;
    """

    print(f"--- Fetching data from database for {start_date} to {end_date}... ---")
    
    data_payload = {}
    
    try:
        with engine.connect() as conn:
            df = pd.read_sql(text(query), conn)
    except Exception as e:
        print(f"Error connecting to or querying database: {e}")
        return {"error": str(e)}

    if df.empty:
        print("⚠️ No data found for the given date range.")
        data_payload['details'] = []
        data_payload['filters'] = {key: [] for key in FILTER_KEYS}
        data_payload['overall_totals'] = {key: [] for key in FILTER_KEYS}
        return data_payload

    # Data cleaning and feature creation
    df['date'] = pd.to_datetime(df['date']).dt.strftime('%Y-%m-%d')
    df['duration_seconds'] = df['duration_seconds'].fillna(0).astype(int)
    df['duration_hhmmss'] = df['duration_seconds'].apply(seconds_to_hhmmss)
    
    # RENAME: Rename the fetched 'project_type_mc' to 'project_type' for consistent dashboard keys
    df.rename(columns={'project_type_mc': 'project_type'}, inplace=True)
    
    cols_order = [
        'id', 'team', 'name', 'date', 'project', 'process', 'sub_process',
        'project_type', # Now using the real data column
        'start_time', 'end_time', 'duration_seconds', 'duration_hhmmss'
    ]
    df_detailed = df[cols_order].copy()
    
    # Fix for JSON Serialization Error (TypeError: Timedelta is not JSON serializable)
    df_detailed['start_time'] = df_detailed['start_time'].astype(str)
    df_detailed['end_time'] = df_detailed['end_time'].astype(str)

    # Generate unique filter lists (now includes 'project_type')
    filter_options = {
        key: sorted(df[key].unique().tolist())
        for key in FILTER_KEYS
    }

    # Pre-calculate overall totals for each filter category
    overall_totals = {}
    for key in FILTER_KEYS:
        summary_df = (
            df.groupby(key)['duration_seconds']
            .sum()
            .reset_index()
            .rename(columns={'duration_seconds': 'total_seconds'})
        )
        summary_df['total_hhmmss'] = summary_df['total_seconds'].apply(seconds_to_hhmmss)
        overall_totals[key] = summary_df.to_dict('records')

    # Store data globally (within the function scope, returned as payload)
    data_payload['details'] = df_detailed.to_dict('records')
    data_payload['filters'] = filter_options
    data_payload['overall_totals'] = overall_totals
    print("--- Data processed successfully! ---")
    
    return data_payload

# ----------------- Flask Application Setup -----------------
app = Flask(__name__)

# --- Function to define wide default dates ---
def get_default_dates() -> tuple[str, str]:
    """Returns a very wide default date range."""
    # Start from a very early date
    default_start = '2000-01-01'
    
    # End 5 years from today to include any future-dated entries
    future_date = date.today() + timedelta(days=5 * 365)
    default_end = future_date.strftime('%Y-%m-%d')
    
    return default_start, default_end
# --------------------------------------------------

# Route to serve the main HTML dashboard
@app.route('/')
def index():
    """Renders the main dashboard HTML page and sets wide default dates."""
    
    default_start, default_end = get_default_dates() 
    
    # Read filter keys from the module scope
    filter_keys_to_pass = FILTER_KEYS
    
    return render_template(
        'index.html', 
        filter_keys=filter_keys_to_pass, # Pass updated filter keys (including project_type)
        default_start_date=default_start, 
        default_end_date=default_end
    )

# API endpoint to provide the processed data to the frontend
@app.route('/api/data', methods=['GET'])
def get_dashboard_data():
    """
    URL query parameters மூலம் கோரப்பட்ட காலவரம்பின் அடிப்படையில் timesheet தரவைத்
    திருப்பி அனுப்புகிறது.
    """
    default_start, default_end = get_default_dates() 

    # URL query parameter-களிலிருந்து தொடக்க மற்றும் இறுதி தேதிகளைப் பெறவும்.
    start_date = request.args.get('start', default_start)
    end_date = request.args.get('end', default_end)

    processed_data = fetch_and_process_data_from_db(start_date, end_date)

    if "error" in processed_data:
        return jsonify({
            "error": "Error loading data from the database.",
            "details": processed_data["error"]
        }), 500
    
    return jsonify(processed_data)

# ----------------- Main Execution -----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001)) 
    print(f"Server starting on http://127.0.0.1:{port}/")
    app.run(debug=True, port=port)
