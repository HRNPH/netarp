use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "scan")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub started_at: DateTimeUtc,
    pub finished_at: Option<DateTimeUtc>,
    pub subnets: String,
    pub interface: String,
    pub status: String,
    pub device_count: Option<i32>,
    pub new_count: Option<i32>,
    pub updated_count: Option<i32>,
    pub failed_count: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    ScanResult,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Relation::ScanResult => Entity::has_many(super::scan_result::Entity).into(),
        }
    }
}

impl Related<super::scan_result::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ScanResult.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
