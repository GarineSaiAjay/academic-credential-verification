//! Paging for list endpoints: a limit, and a cursor that says where the previous page ended ("keyset" paging).
//! Unlike OFFSET, a cursor costs the same on page 1 and page 10,000, and does not skip or repeat rows when
//! new ones arrive while someone is paging.
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

use crate::error::{AppError, Res};

/// The requested page size, defaulting to `default` and never above `max`.
pub fn limit(requested: Option<i64>, default: i64, max: i64) -> i64 {
    requested.unwrap_or(default).clamp(1, max)
}

/// A cursor for lists ordered by (time, id), newest first.
pub fn encode(at: DateTime<Utc>, id: Uuid) -> String {
    format!("{}.{id}", at.timestamp_micros())
}

pub fn decode(cursor: &str) -> Res<(DateTime<Utc>, Uuid)> {
    let bad = || AppError::BadRequest("'before' is not a cursor returned by this endpoint".into());
    let (micros, id) = cursor.split_once('.').ok_or_else(bad)?;
    let at = Utc
        .timestamp_micros(micros.parse().map_err(|_| bad())?)
        .single()
        .ok_or_else(bad)?;
    Ok((at, id.parse().map_err(|_| bad())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_clamped() {
        assert_eq!(limit(None, 50, 200), 50);
        assert_eq!(limit(Some(0), 50, 200), 1);
        assert_eq!(limit(Some(-5), 50, 200), 1);
        assert_eq!(limit(Some(10_000), 50, 200), 200);
        assert_eq!(limit(Some(7), 50, 200), 7);
    }

    #[test]
    fn cursors_round_trip_and_reject_junk() {
        let (at, id) = (
            Utc.timestamp_micros(1_700_000_000_123_456).unwrap(),
            Uuid::new_v4(),
        );
        assert_eq!(decode(&encode(at, id)).unwrap(), (at, id));
        for junk in [
            "",
            "x",
            "1.2",
            "abc.00000000-0000-0000-0000-000000000000",
            "99999999999999999999.00000000-0000-0000-0000-000000000000",
        ] {
            assert!(decode(junk).is_err(), "{junk}");
        }
    }
}
