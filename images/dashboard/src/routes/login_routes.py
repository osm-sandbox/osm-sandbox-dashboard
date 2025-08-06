import logging
import os
import uuid
import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse, RedirectResponse
from requests_oauthlib import OAuth2Session
from models.sessions import Sessions
from datetime import datetime, timedelta, timezone

from urllib.parse import urlparse

# Import database utils
from database import get_db

# Import utils
from utils.osm_credentials import get_osm_credentials
from utils.sandbox_sessions import save_update_box_session, update_user_session
from utils.sandbox_database import save_user_sandbox_db
from utils.box_helpers import is_box_running

from schemas.sessions import SessionResponse, SandboxTokenResponse
import utils.logging_config

# Get OSM credentials
client_id, client_secret, redirect_uri, osm_instance_url, osm_instance_scopes = (
    get_osm_credentials()
)

# Get TM OAuth credentials for sandbox authentication
tm_oauth_client_id = os.getenv("SANDBOX_TM_OAUTH_CLIENT_ID")
tm_oauth_client_secret = os.getenv("SANDBOX_TM_OAUTH_CLIENT_SECRET")  # Original unhashed secret needed for API calls

router = APIRouter()

domain = os.getenv("SANDBOX_DOMAIN")

oauth = OAuth2Session(client_id=client_id, redirect_uri=redirect_uri, scope=osm_instance_scopes)


# Custom static files to set cache control
class CustomStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response


static_path = os.path.join(os.path.dirname(__file__), "./../static")
router.mount("/static", CustomStaticFiles(directory=static_path), name="static")

templates_path = os.path.join(os.path.dirname(__file__), "./../templates")
templates = Jinja2Templates(directory=templates_path)


@router.get("/login_sandbox", tags=["Testing pages"])
def test_page(request: Request, db: Session = Depends(get_db)):
    """Page for login test"""
    return templates.TemplateResponse("login_sandbox.html", {"request": request})


@router.post("/sessions", tags=["OSM Session Sandbox"], response_model=SessionResponse)
def create_session(request: Request, box: str = Query(...), end_redirect_uri: str = Query(None, description="Callback URL to redirect to after authentication"), db: Session = Depends(get_db)):
    """Create a new sandbox session, permitting the user to authenticate to a sandbox"""
    if not is_box_running(db, box):
        raise HTTPException(
            status_code=400, detail=f'The specified box "{box}" is not available yet!'
        )

    session_id = str(uuid.uuid4())
    new_session = Sessions(id=session_id, box=box, end_redirect_uri=end_redirect_uri, created_at=datetime.now(timezone.utc))
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    response = JSONResponse(
        content={
            "id": new_session.id,
            "box": new_session.box,
            "end_redirect_uri": new_session.end_redirect_uri,
            "created_at": new_session.created_at.isoformat(),
        }
    )

    return response


@router.get("/osm_authorization", tags=["OSM Session Sandbox"])
def osm_authorization(
    request: Request, session_id: str = Query(...), db: Session = Depends(get_db)
):
    """Enable OSM authorization"""

    # Verify if session id exists
    session = db.query(Sessions).filter(Sessions.id == session_id).first()
    if session is None:
        logging.error("session_id not found")
        raise HTTPException(status_code=404, detail="session_id not found")

    # Redirect to OSM auth with state parameter
    auth_url = f"{osm_instance_url}/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={osm_instance_scopes}&state={session_id}"
    
    return RedirectResponse(url=auth_url, status_code=303)


@router.get("/redirect_sandbox", tags=["OSM Session Sandbox"])
async def redirect_sandbox(request: Request, code: str, state: str = None, db: Session = Depends(get_db)):
    """Redirect and login in sandbox"""

    try:
        # Get user data
        token = oauth.fetch_token(
            f"{osm_instance_url}/oauth2/token", code=code, client_secret=client_secret
        )
        oauth.token = token
        user_details_response = oauth.get(f"{osm_instance_url}/api/0.6/user/details.json")
        user_details = user_details_response.json()
        display_name = user_details.get("user").get("display_name")
        logging.info(f"Fetched user details for: {display_name}")

        session_id = state
        if session_id:
            session = update_user_session(db, session_id, display_name)

            # Try to save user to sandbox database
            try:
                save_user_sandbox_db(session.box, session.user)
                logging.info(f"Successfully created sandbox user for: {session.user}")
            except Exception as e:
                logging.warning(f"Could not create sandbox user: {e}")
            
            # Get sandbox OAuth token using TM credentials and created user credentials
            try:
                sandbox_api_url = f"https://api.{session.box}.boxes.osmsandbox.us"
                
                response = requests.post(
                    f"{sandbox_api_url}/oauth2/token",
                    data={
                        'grant_type': 'password',
                        'client_id': tm_oauth_client_id,
                        'client_secret': tm_oauth_client_secret,
                        'username': session.user,
                        'password': session.user, # password == username
                        'scope': 'read_prefs write_prefs write_api read_gpx write_notes'
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    sandbox_token_data = response.json()
                    sandbox_access_token = sandbox_token_data.get('access_token')
                    expires_in = sandbox_token_data.get('expires_in', 3600)  # Default 1 hour
                    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                    
                    # Store sandbox token in session
                    session.sandbox_oauth_token = sandbox_access_token
                    session.sandbox_token_expires_at = expires_at
                    db.commit()
                    
                    logging.info(f"Successfully obtained sandbox OAuth token for user: {session.user}")
                else:
                    logging.error(f"Failed to get sandbox OAuth token: {response.status_code} - {response.text}")
                    
            except Exception as e:
                logging.error(f"Error getting sandbox OAuth token: {e}")

            # Redirect to TM callback URL instead of sandbox login
            if session.end_redirect_uri:
                # Replace {{session_id}} placeholder if present
                end_redirect_uri = session.end_redirect_uri.replace('{{session_id}}', session_id)
                logging.info(f"Redirecting to TM callback for session: {session_id}")
                return RedirectResponse(url=end_redirect_uri)
            else:
                # Fallback to sandbox login if no callback URL provided
                end_redirect_uri = f"https://{session.box}.{domain}/login?user={session.user}"
                logging.info(f"No callback URL provided, using sandbox login for user: {session.user}")
                return RedirectResponse(url=end_redirect_uri)
        else:
            logging.error("State parameter not found")
            raise HTTPException(status_code=400, detail="Missing state parameter")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/sessions/{session_id}", tags=["OSM Session Sandbox"], response_model=SandboxTokenResponse)
def get_session(session_id: str, db: Session = Depends(get_db)):
    """Get sandbox OAuth token for a session (one-time use)"""
  
    # Get session from database
    session = db.query(Sessions).filter(Sessions.id == session_id).first()
    if session is None:
        logging.error(f"Session not found: {session_id}")
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Check if token exists
    if not session.sandbox_oauth_token:
        logging.error(f"No sandbox token found for session: {session_id}")
        raise HTTPException(status_code=404, detail="Sandbox token not found")
    
    # Check if token has expired
    if session.sandbox_token_expires_at and session.sandbox_token_expires_at < datetime.now(timezone.utc):
        logging.error(f"Sandbox token expired for session: {session_id}")
        # Clean up expired token
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Token expired")
    
    # Prepare response
    sandbox_api_url = f"https://api.{session.box}.boxes.osmsandbox.us"
    expires_in = None
    if session.sandbox_token_expires_at:
        expires_in = int((session.sandbox_token_expires_at - datetime.now(timezone.utc)).total_seconds())
    
    token_response = SandboxTokenResponse(
        access_token=session.sandbox_oauth_token,
        expires_in=expires_in,
        sandbox_api_url=sandbox_api_url
    )
    
    # One-time use: delete the session after retrieving the token
    db.delete(session)
    db.commit()
    logging.info(f"Session {session_id} token retrieved and deleted")
    
    return token_response
