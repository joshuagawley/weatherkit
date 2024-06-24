// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod auth;
pub mod error;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const WEATHERKIT_API_BASE_URL: &str = "https://weatherkit.apple.com/api/v1";

/// The system of units that the weather data is reported in.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum UnitsSystem {
    /// Metric
    M,
}

/// Descriptive information about the weather data.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// The URL of the legal attribution for the data source.
    pub attribution_url: Option<String>,
    /// The time when the weather data is no longer valid.
    pub expire_time: DateTime<Utc>,
    /// The ISO language code for localizable fields.
    pub language: Option<String>,
    /// The latitude of the relevant location.
    pub latitude: f64,
    /// The longitude of the relevant location.
    pub longitude: f64,
    /// The longitude of the relevant location.
    pub provider_logo: Option<String>,
    /// The longitude of the relevant location.
    pub provider_name: Option<String>,
    /// The time the weather data was procured.
    pub read_time: DateTime<Utc>,
    /// The time the provider reported the weather data.
    pub reported_time: Option<DateTime<Utc>>,
    /// Whether the weather data is temporarily unavailable from the provider.
    pub temporarily_unavailable: Option<bool>,
    /// The system of units that the weather data is reported in.
    /// This is always set to metric.
    pub units: Option<UnitsSystem>,
    /// The data format version.
    pub version: i64,
}

/// The direction of change of the sea level air pressure.
#[derive(Eq, PartialEq, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum PressureTrend {
    /// The sea level air pressure is increasing.
    Rising,
    /// The sea level air pressure is decreasing.
    Falling,
    /// The sea level air pressure is remaining about the same..
    Steady,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CurrentWeather {
    /// Descriptive information about the weather data.
    pub metadata: Metadata,
    /// The date and time.
    pub as_of: DateTime<Utc>,
    /// The percentage of the sky covered with clouds during the period, from 0 to 1.
    pub cloud_cover: Option<f64>,
    /// An enumeration value indicating the condition at the time.
    pub condition_code: String,
    /// A Boolean value indicating whether there is daylight.
    pub daylight: Option<bool>,
    /// The relative humidity, from 0 to 1.
    pub humidity: f64,
    /// The precipitation intensity, in millimeters per hour.
    pub precipitation_intensity: f64,
    /// The sea level air pressure, in millibars.
    pub pressure: f64,
    /// The direction of change of the sea level air pressure.
    pub pressure_trend: PressureTrend,
    /// The current temperature, in degrees Celsius.
    pub temperature: f64,
    /// The feels-like temperature when factoring wind and humidity, in degrees Celsius.
    pub temperature_apparent: f64,
    /// The temperature at which relative humidity is 100%, in Celsius.
    pub temperature_dew_point: f64,
    /// The level of ultraviolet radiation.
    pub uv_index: u8,
    /// The distance at which terrain is visible, in meters.
    pub visibility: f64,
    /// The direction of the wind, in degrees.
    pub wind_direction: Option<u16>,
    /// The maximum wind gust speed, in kilometers per hour.
    pub wind_gust: Option<f64>,
    /// The wind speed, in kilometers per hour.
    pub wind_speed: f64,
}

/// The type of precipitation forecasted to occur during the day.
#[derive(Eq, PartialEq, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum PrecipitationType {
    /// No precipitation is occurring.
    Clear,
    /// An unknown type of precipitation is occurring.
    Precipitation,
    /// Rain or freezing rain is falling.
    Rain,
    /// Snow is falling.
    Snow,
    /// Sleet or ice pellets are falling.
    Sleet,
    /// Hail is falling
    Hail,
    /// Winter weather (wintery mix or wintery showers) is falling.
    Mixed,
}

/// THe shape of the moon as seen by the observer on the ground at a given time.
#[derive(Eq, PartialEq, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum MoonPhase {
    /// The moon isn't visible.
    New,
    /// A crescent-shaped sliver of the moon is visible, and increasing in size.
    WaxingCrescent,
    /// Approximately half of the moon is visible, and increasing in size.,
    FirstQuarter,
    /// The entire disc of the moon is visible.
    Full,
    /// More than half of the moon is visible, and increasing in size.
    WaxingGibbous,
    /// More than half of the moon is visible, and decreasing in size.
    WaningGibbous,
    /// Approximately half of the moon is visible, and decreasing in size.
    ThirdQuarter,
    /// A crescent-shaped sliver of the moon is visible, and decreasing in size.
    WaningCrescent,
}

/// A summary forecast for a daytime or overnight period.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DayPartForecast {
    /// The percentage of the sky covered with clouds during the period, from 0 to
    pub cloud_cover: f64,
    /// An enumeration value indicating the condition at the time.
    pub condition_code: String,
    /// The ending date and time of the forecast.
    pub forecast_end: DateTime<Utc>,
    /// The starting date and time of the forecast.
    pub forecast_start: DateTime<Utc>,
    /// The relative humidity during the period, from 0 to 1.
    pub humidity: f64,
    /// The amount of precipitation forecasted to occur during the period, in millimeters.
    pub precipitation_amount: f64,
    /// The chance of precipitation forecasted to occur during the period.
    pub precipitation_chance: f64,
    /// The type of precipitation forecasted to occur during the period.
    pub precipitation_type: PrecipitationType,
    /// The depth of snow as ice crystals forecasted to occur during the period, in millimeters.
    pub snowfall_amount: f64,
    /// The direction the wind is forecasted to come from during the period, in degrees.
    pub wind_direction: Option<u16>,
    /// The average speed the wind is forecasted to be during the period, in kilometers per hour.
    pub wind_speed: f64,
}

/// The historical or forecasted weather conditions for a specified day.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DayWeatherConditions {
    /// An enumeration value indicating the condition at the time.
    pub condition_code: String,
    /// The forecast between 7 AM and 7 PM for the day.
    pub daytime_forecast: Option<DayPartForecast>,
    /// The ending date and time of the day.
    pub forecast_end: DateTime<Utc>,
    /// The starting date and time of the day.
    pub forecast_start: DateTime<Utc>,
    /// The maximum ultraviolet index value during the day.
    pub max_uv_index: u8,
    /// The phase of the moon on the specified day.
    pub moon_phase: MoonPhase,
    /// The time of moonrise on the specified day.
    pub moonrise: Option<DateTime<Utc>>,
    /// The time of moonset on the specified day.
    pub moonset: Option<DateTime<Utc>>,
    /// The day part forecast between 7 PM and 7 AM for the overnight.
    pub overnight_forecast: Option<DayPartForecast>,
    /// The amount of precipitation forecasted to occur during the day, in millimeters.
    pub precipitation_amount: f64,
    /// The chance of precipitation forecasted to occur during the day.
    pub precipitation_chance: f64,
    /// The type of precipitation forecasted to occur during the day.
    pub precipitation_type: PrecipitationType,
    /// The depth of snow as ice crystals forecasted to occur during the day, in millimeters.
    pub snowfall_amount: f64,
    /// The time when the sun is lowest in the sky.
    pub solar_midnight: Option<DateTime<Utc>>,
    /// The time when the sun is highest in the sky.
    pub solar_noon: Option<DateTime<Utc>>,
    /// The time when the top edge of the sun reaches the horizon in the morning.
    pub sunrise: Option<DateTime<Utc>>,
    /// The time when the sun is 18 degrees below the horizon in the morning.
    pub sunrise_astronomical: Option<DateTime<Utc>>,
    /// The time when the sun is 6 degrees below the horizon in the morning.
    pub sunrise_civil: Option<DateTime<Utc>>,
    /// The time when the sun is 12 degrees below the horizon in the morning.
    pub sunrise_nautical: Option<DateTime<Utc>>,
    /// The time when the top edge of the sun reaches the horizon in the evening.
    pub sunset: Option<DateTime<Utc>>,
    /// The time when the sun is 18 degrees below the horizon in the evening.
    pub sunset_astronomical: Option<DateTime<Utc>>,
    /// The time when the sun is 6 degrees below the horizon in the evening.
    pub sunset_civil: Option<DateTime<Utc>>,
    /// The time when the sun is 12 degrees below the horizon in the evening.
    pub sunset_nautical: Option<DateTime<Utc>>,
    /// The maximum temperature forecasted to occur during the day, in degrees Celsius.
    pub temperature_max: f64,
    /// The minimum temperature forecasted to occur during the day, in degrees Celsius.
    pub temperature_min: f64,
}

/// A collection of day forecasts for a specified range of days.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DailyForecast {
    /// Descriptive information about the weather data.
    pub metadata: Metadata,
    /// An array of the day forecast weather conditions.
    pub days: Vec<DayWeatherConditions>,
    /// A URL that provides more information about the forecast.
    pub learn_more_url: Option<String>,
}

/// The historical or forecasted weather conditions for a specified hour.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HourWeatherConditions {
    /// The percentage of the sky covered with clouds during the period, from 0 to 1.
    pub cloud_cover: f64,
    /// An enumeration value indicating the condition at the time.
    pub condition_code: String,
    /// Indicates whether the hour starts during the day or night.
    pub daylight: Option<bool>,
    /// The starting date and time of the forecast.
    pub forecast_start: DateTime<Utc>,
    /// The relative humidity at the start of the hour, from 0 to 1.
    pub humidity: f64,
    /// The chance of precipitation forecasted to occur during the hour, from 0 to 1.
    pub precipitation_chance: f64,
    /// The type of precipitation forecasted to occur during the period.
    pub precipitation_type: PrecipitationType,
    /// The sea-level air pressure, in millibars.
    pub pressure: f64,
    /// The direction of change of the sea-level air pressure.
    pub pressure_trend: Option<PressureTrend>,
    /// The rate at which snow crystals are falling, in millimeters per hour.
    pub snowfall_intensity: Option<f64>,
    /// The temperature at the start of the hour, in degrees Celsius.
    pub temperature: f64,
    /// The temperature at the start of the hour, in degrees Celsius.
    pub temperature_apparent: f64,
    /// The temperature at which relative humidity is 100% at the top of the hour, in degrees Celsius.
    pub temperature_dew_point: Option<f64>,
    /// The level of ultraviolet radiation at the start of the hour.
    pub uv_index: u8,
    /// The distance at which terrain is visible at the start of the hour, in meters.
    pub visibility: f64,
    /// The direction of the wind at the start of the hour, in degrees.
    pub wind_direction: Option<u16>,
    /// The maximum wind gust speed during the hour, in kilometers per hour.
    pub wind_gust: Option<f64>,
    /// The wind speed at the start of the hour, in kilometers per hour.
    pub wind_speed: f64,
    /// The amount of precipitation forecasted to occur during period, in millimeters.
    pub precipitation_amount: Option<f64>,
}

/// A collection of hour forecasts for a specified range of hours.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HourlyForecast {
    /// Descriptive information about the weather data.
    pub metadata: Metadata,
    /// An array of hourly forecasts.
    pub hours: Vec<HourWeatherConditions>,
}

/// The precipitation forecast for a specified minute.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForecastMinute {
    /// The probability of precipitation during this minute.
    pub precipitation_chance: f64,
    /// The precipitation intensity in millimeters per hour.
    pub precipitation_intensity: f64,
    /// The start time of the minute.
    pub start_time: DateTime<Utc>,
}

/// The summary for a specified period in the minute forecast.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ForecastPeriodSummary {
    /// The type of precipitation forecasted.
    pub condition: PrecipitationType,
    /// The end time of the forecast.
    pub end_time: Option<DateTime<Utc>>,
    /// The probability of precipitation during this period.
    pub precipitation_chance: f64,
    /// The precipitation intensity in millimeters per hour.
    pub precipitation_intensity: f64,
    /// The start time of the forecast.
    pub start_time: DateTime<Utc>,
}

/// The next hour forecast information.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NextHourForecast {
    /// Descriptive information about the weather data.
    pub metadata: Metadata,
    /// The time the forecast ends.
    pub forecast_end: Option<DateTime<Utc>>,
    /// The time the forecast starts.
    pub forecast_start: Option<DateTime<Utc>>,
    /// The time the forecast ends.
    pub minutes: Vec<ForecastMinute>,
    /// An array of the forecast summaries.
    pub summary: Vec<ForecastPeriodSummary>,
}

/// How likely the event is to occur.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Certainty {
    /// The event has already occurred or is ongoing.
    Observed,
    /// The event is likely to occur (greater than 50% probability).
    Likely,
    /// The event is unlikely to occur (less than 50% probability).
    Possible,
    /// The event is not expected to occur (approximately 0% probability)..
    Unlikely,
    /// It is unknown if the event will occur.
    Unknown,
}

/// The recommended action from a reporting agency.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ResponseType {
    /// Take shelter in place.
    Shelter,
    /// Relocate.
    Evacuate,
    /// Make preparations
    Prepare,
    /// Execute a pre-planned activity.
    Execute,
    /// Avoid the event.
    Avoid,
    /// Monitor the situation.
    Monitor,
    /// Assess the situation.
    Assess,
    /// The event no longer poses a threat.
    AllClear,
    /// No action recommended.
    None,
}

/// The level of danger to life and property.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    /// Extraordinary threat.
    Extreme,
    /// Significant threat.
    Severe,
    /// Possible threat.
    Moderate,
    /// Minimal or no known threat.
    Minor,
    /// Unknown threat.
    Unknown,
}

/// An indication of urgency of action from the reporting agency.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Urgency {
    /// Take responsive action immediately.
    Immediate,
    /// Take responsive action in the next hour.
    Expected,
    /// Take responsive action in the near future.
    Future,
    /// Responsive action is no longer required.
    Past,
    /// The urgency is unknown.
    Unknown,
}

/// Detailed information about the weather alert.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WeatherAlertSummary {
    /// An official designation of the affected area.
    pub area_id: Option<String>,
    /// A human-readable name of the affected area.
    pub area_name: Option<String>,
    /// How likely the event is to occur.
    pub certainty: Certainty,
    /// The ISO code of the reporting country.
    pub country_code: String,
    /// A human-readable description of the event.
    pub description: String,
    /// The URL to a page containing detailed information about the event.
    pub details_url: Option<String>,
    /// The time the event went into effect.
    pub effective_time: DateTime<Utc>,
    /// The time when the underlying weather event is projected to end.
    pub event_end_time: Option<DateTime<Utc>>,
    /// The time when the underlying weather event is projected to start.
    pub event_onset_time: Option<DateTime<Utc>>,
    /// The time when the event expires.
    pub expire_time: DateTime<Utc>,
    /// A unique identifier of the event.
    pub id: String,
    /// The time that event was issued by the reporting agency.
    pub issued_time: DateTime<Utc>,
    /// An array of recommended actions from the reporting agency.
    pub responses: Vec<ResponseType>,
    /// The level of danger to life and property.
    pub severity: Severity,
    /// The name of the reporting agency.
    pub source: String,
    /// An indication of urgency of action from the reporting agency.
    pub urgency: Option<Urgency>,
}

/// A collecton of weather alerts.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WeatherAlertsCollection {
    /// An array of weather alert summaries.
    pub alerts: Vec<WeatherAlertSummary>,
    /// A URL that provides more information about the alerts.
    pub details_url: Option<String>,
}

/// The collection of all requested weather data.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Weather {
    /// The current weather for the requested location.
    pub current_weather: Option<CurrentWeather>,
    /// The daily forecast for the requested location.
    pub forecast_daily: Option<DailyForecast>,
    /// The hourly forecast for the requested location.
    pub forecast_hourly: Option<HourlyForecast>,
    /// The next hour forecast for the requested location.
    pub forecast_next_hour: Option<NextHourForecast>,
    /// Weather alerts for the requested location.
    pub weather_alerts: Option<WeatherAlertsCollection>,
}

/// The collection of weather information for a location.
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum DataSet {
    /// The current weather for the requested location.
    CurrentWeather,
    /// The daily forecast for the requested location.
    ForecastDaily,
    /// The hourly forecast for the requested location.
    ForecastHourly,
    /// The next hour forecast for the requested location.
    ForecastNextHour,
    /// The next hour forecast for the requested location.
    WeatherAlerts,
}

impl DataSet {
    pub const fn fmt(&self) -> &str {
        match self {
            DataSet::CurrentWeather => "currentWeather",
            DataSet::ForecastDaily => "forecastDaily",
            DataSet::ForecastHourly => "forecastHourly",
            DataSet::ForecastNextHour => "forecastNextHour",
            DataSet::WeatherAlerts => "weatherAlerts",
        }
    }
}
