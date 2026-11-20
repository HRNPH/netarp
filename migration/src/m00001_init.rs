use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Device::Table)
                    .if_not_exists()
                    .col(string_len(Device::Mac, 17).primary_key())
                    .col(string(Device::Ip))
                    .col(string_null(Device::Alias))
                    .col(string_null(Device::Vendor))
                    .col(timestamp(Device::FirstSeen))
                    .col(timestamp(Device::LastSeen))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Event::Table)
                    .if_not_exists()
                    .col(pk_auto(Event::Id))
                    .col(string(Event::DeviceMac))
                    .col(timestamp(Event::Timestamp))
                    .col(string(Event::Kind))
                    .col(string_null(Event::Detail))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_event_device")
                            .from(Event::Table, Event::DeviceMac)
                            .to(Device::Table, Device::Mac)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Scan::Table)
                    .if_not_exists()
                    .col(pk_auto(Scan::Id))
                    .col(timestamp(Scan::StartedAt))
                    .col(timestamp_null(Scan::FinishedAt))
                    .col(string(Scan::Subnets))
                    .col(string(Scan::Interface))
                    .col(string(Scan::Status))
                    .col(integer_null(Scan::DeviceCount))
                    .col(integer_null(Scan::NewCount))
                    .col(integer_null(Scan::UpdatedCount))
                    .col(integer_null(Scan::FailedCount))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ScanResult::Table)
                    .if_not_exists()
                    .col(pk_auto(ScanResult::Id))
                    .col(integer(ScanResult::ScanId))
                    .col(string(ScanResult::Ip))
                    .col(string(ScanResult::Mac))
                    .col(string(ScanResult::Status))
                    .col(string_null(ScanResult::Error))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_scan_result_scan")
                            .from(ScanResult::Table, ScanResult::ScanId)
                            .to(Scan::Table, Scan::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_device_last_seen")
                    .table(Device::Table)
                    .col(Device::LastSeen)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_event_mac_ts")
                    .table(Event::Table)
                    .col(Event::DeviceMac)
                    .col(Event::Timestamp)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_scan_started_at")
                    .table(Scan::Table)
                    .col(Scan::StartedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_scan_result_scan_id")
                    .table(ScanResult::Table)
                    .col(ScanResult::ScanId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ScanResult::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Scan::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Event::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Device::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Device {
    Table,
    Mac,
    Ip,
    Alias,
    Vendor,
    FirstSeen,
    LastSeen,
}

#[derive(DeriveIden)]
enum Event {
    Table,
    Id,
    DeviceMac,
    Timestamp,
    Kind,
    Detail,
}

#[derive(DeriveIden)]
enum Scan {
    Table,
    Id,
    StartedAt,
    FinishedAt,
    Subnets,
    Interface,
    Status,
    DeviceCount,
    NewCount,
    UpdatedCount,
    FailedCount,
}

#[derive(DeriveIden)]
enum ScanResult {
    Table,
    Id,
    ScanId,
    Ip,
    Mac,
    Status,
    Error,
}
