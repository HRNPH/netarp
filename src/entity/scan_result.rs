use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "scan_result")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub scan_id: i32,
    pub ip: String,
    pub mac: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Scan,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Relation::Scan => Entity::belongs_to(super::scan::Entity)
                .from(Column::ScanId)
                .to(super::scan::Column::Id)
                .on_delete(ForeignKeyAction::Cascade)
                .on_update(ForeignKeyAction::Cascade)
                .into(),
        }
    }
}

impl Related<super::scan::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Scan.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
