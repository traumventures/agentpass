//! The unlock-duration picker.

use yew::prelude::*;

const PRESETS: [(u64, &str); 4] = [
    (15 * 60, "15 min"),
    (3600, "1 hour"),
    (8 * 3600, "8 hours"),
    (24 * 3600, "24 hours"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Minutes,
    Hours,
    Days,
}

impl Unit {
    fn secs(self) -> u64 {
        match self {
            Unit::Minutes => 60,
            Unit::Hours => 3600,
            Unit::Days => 86400,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum DurationChoice {
    Preset(u64),
    Custom { amount: String, unit: Unit },
    UntilLocked,
}

impl DurationChoice {
    /// Initial selection from the agent's suggestion (`Some(0)` = until locked).
    pub fn from_suggestion(s: Option<u64>) -> Self {
        match s {
            None => Self::Preset(3600),
            Some(0) => Self::UntilLocked,
            Some(s) if PRESETS.iter().any(|(p, _)| *p == s) => Self::Preset(s),
            Some(s) if s.is_multiple_of(86400) => Self::Custom {
                amount: (s / 86400).to_string(),
                unit: Unit::Days,
            },
            Some(s) if s.is_multiple_of(3600) => Self::Custom {
                amount: (s / 3600).to_string(),
                unit: Unit::Hours,
            },
            Some(s) => Self::Custom {
                amount: s.div_ceil(60).to_string(),
                unit: Unit::Minutes,
            },
        }
    }

    /// Seconds to send to the daemon (`None` = until locked), or why the
    /// input is invalid.
    pub fn seconds(&self, max: u64) -> Result<Option<u64>, String> {
        match self {
            Self::Preset(s) => Ok(Some(*s)),
            Self::UntilLocked => Ok(None),
            Self::Custom { amount, unit } => {
                let n: u64 = amount
                    .trim()
                    .parse()
                    .map_err(|_| "Enter a whole number for the custom duration.".to_owned())?;
                let secs = n.saturating_mul(unit.secs());
                if secs == 0 {
                    Err("The duration must be greater than zero.".into())
                } else if secs > max {
                    Err(format!(
                        "At most {}. Choose “Until locked” for longer.",
                        describe(max)
                    ))
                } else {
                    Ok(Some(secs))
                }
            }
        }
    }
}

pub fn describe(secs: u64) -> String {
    let plural = |n: u64, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
    if secs.is_multiple_of(86400) {
        plural(secs / 86400, "day")
    } else if secs.is_multiple_of(3600) {
        plural(secs / 3600, "hour")
    } else {
        plural(secs.div_ceil(60), "minute")
    }
}

#[derive(Properties, PartialEq)]
pub struct PickerProps {
    pub value: DurationChoice,
    pub onchange: Callback<DurationChoice>,
    pub max: u64,
}

#[function_component(DurationPicker)]
pub fn duration_picker(props: &PickerProps) -> Html {
    let pick = |c: DurationChoice| {
        let cb = props.onchange.clone();
        Callback::from(move |_: Event| cb.emit(c.clone()))
    };
    let (amount, unit) = match &props.value {
        DurationChoice::Custom { amount, unit } => (amount.clone(), *unit),
        _ => ("2".to_owned(), Unit::Hours),
    };
    let is_custom = matches!(props.value, DurationChoice::Custom { .. });

    let on_amount = {
        let cb = props.onchange.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            cb.emit(DurationChoice::Custom {
                amount: input.value(),
                unit,
            });
        })
    };
    let on_unit = {
        let cb = props.onchange.clone();
        let amount = amount.clone();
        Callback::from(move |e: Event| {
            let select: web_sys::HtmlSelectElement = e.target_unchecked_into();
            let unit = match select.value().as_str() {
                "m" => Unit::Minutes,
                "d" => Unit::Days,
                _ => Unit::Hours,
            };
            cb.emit(DurationChoice::Custom {
                amount: amount.clone(),
                unit,
            });
        })
    };

    html! {
        <div class="durations" role="radiogroup">
            { for PRESETS.iter().map(|(secs, label)| html! {
                <label class={classes!("chip", (props.value == DurationChoice::Preset(*secs)).then_some("selected"))}>
                    <input type="radio" name="duration" checked={props.value == DurationChoice::Preset(*secs)}
                        onchange={pick(DurationChoice::Preset(*secs))} />
                    { *label }
                </label>
            }) }
            <label class={classes!("chip", is_custom.then_some("selected"))}>
                <input type="radio" name="duration" checked={is_custom}
                    onchange={pick(DurationChoice::Custom { amount: amount.clone(), unit })} />
                { "Custom" }
            </label>
            <label class={classes!("chip", "forever", (props.value == DurationChoice::UntilLocked).then_some("selected"))}>
                <input type="radio" name="duration" checked={props.value == DurationChoice::UntilLocked}
                    onchange={pick(DurationChoice::UntilLocked)} />
                { "Until locked" }
            </label>
            if is_custom {
                <div class="custom">
                    <input type="number" min="1" step="1" aria-label="Custom duration" value={amount} oninput={on_amount} />
                    <select aria-label="Unit" onchange={on_unit}>
                        <option value="m" selected={unit == Unit::Minutes}>{ "minutes" }</option>
                        <option value="h" selected={unit == Unit::Hours}>{ "hours" }</option>
                        <option value="d" selected={unit == Unit::Days}>{ "days" }</option>
                    </select>
                </div>
            }
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_map_to_choices() {
        assert!(DurationChoice::from_suggestion(None) == DurationChoice::Preset(3600));
        assert!(DurationChoice::from_suggestion(Some(0)) == DurationChoice::UntilLocked);
        assert!(DurationChoice::from_suggestion(Some(900)) == DurationChoice::Preset(900));
        assert!(
            DurationChoice::from_suggestion(Some(2 * 86400))
                == DurationChoice::Custom {
                    amount: "2".into(),
                    unit: Unit::Days
                }
        );
        assert!(
            DurationChoice::from_suggestion(Some(90 * 60))
                == DurationChoice::Custom {
                    amount: "90".into(),
                    unit: Unit::Minutes
                }
        );
    }

    #[test]
    fn custom_durations_are_validated() {
        let max = 30 * 86400;
        let c = |a: &str, unit| DurationChoice::Custom {
            amount: a.into(),
            unit,
        };
        assert_eq!(c("3", Unit::Hours).seconds(max), Ok(Some(3 * 3600)));
        assert!(c("0", Unit::Hours).seconds(max).is_err());
        assert!(c("x", Unit::Hours).seconds(max).is_err());
        assert!(c("31", Unit::Days).seconds(max).is_err());
        assert_eq!(DurationChoice::UntilLocked.seconds(max), Ok(None));
        assert_eq!(describe(3600), "1 hour");
        assert_eq!(describe(30 * 86400), "30 days");
    }
}
