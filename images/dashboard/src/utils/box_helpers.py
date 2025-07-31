from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import logging
import asyncio

from models.boxes import Boxes, StateEnum
from schemas.boxes import BoxResponse
from utils.kubectl import normalize_status, describe_release_pods
import utils.logging_config


def is_box_running(db: Session, box_name: str) -> bool:
    """Check if the box is in the "Running" state"""
    box_record = db.query(Boxes).filter(Boxes.name == box_name).order_by(Boxes.id.desc()).first()

    if box_record and box_record.state == StateEnum.running:
        return True
    return False


async def check_release_status(namespace: str, box_id: int, db: Session):
    logging.info(f"Start state checker job for box ID {box_id}")

    end_time = datetime.utcnow() + timedelta(minutes=5)

    while datetime.utcnow() < end_time:
        logging.info(f"Check state for box ID {box_id}")

        # Query the db_box within the current session
        db_box = db.query(Boxes).get(box_id)
        if db_box is None:
            logging.error(f"Box with ID {box_id} not found.")
            return

        if db_box.state == StateEnum.running:
            logging.info(f"Box {db_box.name} is already running.")
            return

        all_pods_running = await describe_release_pods(namespace, db_box.name)
        if all_pods_running:
            logging.info(f"All pods for box {db_box.name} are running.")
            # Update the state to Running
            db_box.state = StateEnum.running
            db.commit()
            db.refresh(db_box)
            return

        await asyncio.sleep(20)

    logging.error(f"Box {db_box.name} did not reach running state within the expected time.")
    db_box.state = StateEnum.failure
    db.commit()
    db.refresh(db_box)


def update_box_state_and_age(
    db: Session, box_name: str, releases: list, pod_info: dict
) -> Optional[BoxResponse]:

    db_box = db.query(Boxes).filter(Boxes.name == box_name).order_by(Boxes.id.desc()).first()

    if not db_box:
        return None

    if db_box.state == StateEnum.running:
        box_response = BoxResponse.from_orm(db_box)
        return box_response

    release = next((r for r in releases if r["name"] == box_name), None)
    if release:
        pods = pod_info.get(release["name"], [])
        release_status = [pod.get("state") for pod in pods]
        normalized_status = normalize_status(release_status)
        release["state"] = normalized_status

        if normalized_status == "Running":
            db_box.state = StateEnum.running
        elif normalized_status == "Pending":
            db_box.state = StateEnum.pending
        else:
            db_box.state = StateEnum.failure

        db.commit()
        db.refresh(db_box)

    # Calculate age based on current datetime and start datetime
    current_datetime = datetime.utcnow()
    age_timedelta = current_datetime - db_box.start_date
    age_in_hours = round(age_timedelta.total_seconds() / 3600, 2)

    db_box.age = age_in_hours
    db.commit()
    db.refresh(db_box)

    box_response = BoxResponse.from_orm(db_box)
    box_response.age = age_in_hours

    return box_response
