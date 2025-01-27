use mail_builder::{
    headers::{
        address::{Address, EmailAddress}, // 引入地址和电子邮件地址
        HeaderType, // 引入头类型
    },
    MessageBuilder, // 引入消息构建器
};
use trc::{Collector, MetricType, TelemetryEvent, TOTAL_EVENT_COUNT}; // 引入trc库中的收集器、指标类型、遥测事件和总事件计数

use super::{AlertContent, AlertContentToken, AlertMethod}; // 引入警报内容、警报内容令牌和警报方法
use crate::{
    expr::{functions::ResolveVariable, Variable}, // 引入表达式函数和变量
    Server, // 引入服务器
};
use std::fmt::Write; // 引入写入模块

// 定义AlertMessage结构体，用于表示警报消息
#[derive(Debug, PartialEq, Eq)]
pub struct AlertMessage {
    pub from: String, // 发件人
    pub to: Vec<String>, // 收件人
    pub body: Vec<u8>, // 消息体
}

// 定义CollectorResolver结构体
struct CollectorResolver;

// 为Server结构体实现方法
impl Server {
    // 定义process_alerts方法，用于处理警报
    pub async fn process_alerts(&self) -> Option<Vec<AlertMessage>> {
        let alerts = &self.core.enterprise.as_ref()?.metrics_alerts; // 获取企业版的指标警报
        if alerts.is_empty() {
            return None;
        }
        let mut messages = Vec::new(); // 初始化消息向量

        for alert in alerts {
            if !self
                .eval_expr(&alert.condition, &CollectorResolver, &alert.id, 0)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            for method in &alert.method {
                match method {
                    AlertMethod::Email {
                        from_name,
                        from_addr,
                        to,
                        subject,
                        body,
                    } => {
                        messages.push(AlertMessage {
                            from: from_addr.clone(),
                            to: to.clone(),
                            body: MessageBuilder::new()
                                .from(Address::Address(EmailAddress {
                                    name: from_name.as_ref().map(|s| s.into()),
                                    email: from_addr.as_str().into(),
                                }))
                                .header(
                                    "To",
                                    HeaderType::Address(Address::List(
                                        to.iter()
                                            .map(|to| {
                                                Address::Address(EmailAddress {
                                                    name: None,
                                                    email: to.as_str().into(),
                                                })
                                            })
                                            .collect(),
                                    )),
                                )
                                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                                .subject(subject.build())
                                .text_body(body.build())
                                .write_to_vec()
                                .unwrap_or_default(),
                        });
                    }
                    AlertMethod::Event { message } => {
                        trc::event!(
                            Telemetry(TelemetryEvent::Alert),
                            Id = alert.id.to_string(),
                            Details = message.as_ref().map(|m| m.build())
                        );

                        #[cfg(feature = "test_mode")]
                        Collector::update_event_counter(
                            trc::EventType::Telemetry(TelemetryEvent::Alert),
                            1,
                        );
                    }
                }
            }
        }

        (!messages.is_empty()).then_some(messages)
    }
}

// 为CollectorResolver结构体实现ResolveVariable trait
impl ResolveVariable for CollectorResolver {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        if (variable as usize) < TOTAL_EVENT_COUNT {
            Variable::Integer(Collector::read_event_metric(variable as usize) as i64)
        } else if let Some(metric_type) =
            MetricType::from_code(variable as u64 - TOTAL_EVENT_COUNT as u64)
        {
            Variable::Float(Collector::read_metric(metric_type))
        } else {
            Variable::Integer(0)
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

// 为AlertContent结构体实现方法
impl AlertContent {
    pub fn build(&self) -> String {
        let mut buf = String::with_capacity(self.len());
        for token in &self.0 {
            token.write(&mut buf);
        }
        buf
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.iter().map(|t| t.len()).sum()
    }
}

// 为AlertContentToken结构体实现方法
impl AlertContentToken {
    fn write(&self, buf: &mut String) {
        match self {
            AlertContentToken::Text(text) => buf.push_str(text),
            AlertContentToken::Metric(metric_type) => {
                let _ = write!(buf, "{}", Collector::read_metric(*metric_type));
            }
            AlertContentToken::Event(event_type) => {
                let _ = write!(buf, "{}", Collector::read_event_metric(event_type.id()));
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            AlertContentToken::Text(s) => s.len(),
            AlertContentToken::Metric(_) | AlertContentToken::Event(_) => 10,
        }
    }
}
