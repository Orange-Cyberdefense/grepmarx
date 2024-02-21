# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""
from crypt import methods
import json
import os

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from app import db
from app.constants import OWASP_TOP10_LINKS, RULES_PATH
from app.rules import blueprint
from app.rules.forms import RulePackForm, RulesAddForm
from app.rules.models import Rule, RulePack, SupportedLanguage
from app.rules.util import (
    comma_separated_to_list,
    save_rule_in_db,
    validate_languages_rules,
    sync_db,
    add_new_rule,
    get_languages_names,
)


@blueprint.route("/rules")
@login_required
def rules_list():
    rules = Rule.query.all()
    return render_template(
        "rules_list.html",
        rules=rules,
        owasp_links=OWASP_TOP10_LINKS,
        user=current_user,
        segment="rules",
    )


@blueprint.route("/rules/sync")
@login_required
def rules_sync():
    current_app.logger.info("Started rules sync")
    sync_db(RULES_PATH)
    current_app.logger.info("Finished rules sync")
    return "done", 200


# TODO: do this client side somehow
@blueprint.route("/rules/sync_success")
@login_required
def rules_sync_success():
    flash("Rules were successfully synced", "success")
    return redirect(url_for("rules_blueprint.rules_list"))


@blueprint.route("/rules/details/<rule_id>")
@login_required
def rules_details(rule_id):
    rule = Rule.query.filter_by(id=rule_id).first_or_404()
    file = os.path.join(RULES_PATH, rule.file_path)
    with open(file, "r") as f:
        rule_content = f.read()
    return render_template("rules_details.html", rule=rule, rule_content=rule_content)


@blueprint.route("/rules/packs")
@login_required
def rule_packs_list():
    rule_packs = RulePack.query.all()
    return render_template(
        "rules_packs_list.html",
        rule_packs=rule_packs,
        user=current_user,
        segment="rule_packs",
    )


def rule_packs_form_page(edit, rule_pack_form):
    # Dynamically adds choices for multiple selection fields
    rule_pack_form.languages.choices = (
        (l.id, l.name) for l in SupportedLanguage.query.all()
    )
    rules = Rule.query.all()
    languages_names = get_languages_names()
    # listed_languages = SupportedLanguage.query.rules
    return render_template(
        "rules_packs_edit.html",
        edit=edit,
        rules=rules,
        form=rule_pack_form,
        owasp_links=OWASP_TOP10_LINKS,
        user=current_user,
        segment="rule_packs",
        languages=languages_names
    )


@blueprint.route("/rules/packs/create", methods=["GET", "POST"])
@login_required
def rules_packs_create():
    rule_pack_form = RulePackForm()
    # Dynamically adds choices for multiple selection fields
    rule_pack_form.languages.choices = list(
        (l.id, l.name) for l in SupportedLanguage.query.all()
    )
    # POST / Form submitted
    if "save-rule-pack" in request.form:
        # Form is valid
        if rule_pack_form.validate_on_submit():
            # Perform additional custom validation
            err = validate_languages_rules(rule_pack_form)
            if err is not None:
                flash(err, "error")
                return rule_packs_form_page(edit=False, rule_pack_form=rule_pack_form)
            # Set applicable languages
            rp_languages = SupportedLanguage.query.filter(
                SupportedLanguage.id.in_(rule_pack_form.languages.data)
            ).all()
            # Get associated rules
            rule_ids = comma_separated_to_list(rule_pack_form.rules.data)
            rp_rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()
            # Create the rule pack
            rule_pack = RulePack(
                name=rule_pack_form.name.data,
                description=rule_pack_form.description.data,
                languages=rp_languages,
                rules=rp_rules,
            )
            db.session.add(rule_pack)
            db.session.commit()
            current_app.logger.info(
                "New rule pack added (rule_pack.id=%i)", rule_pack.id
            )
            flash("Rule pack has been successfully created", "success")
            return redirect(url_for("rules_blueprint.rule_packs_list"))
        # Form is invalid, form.error is populated
        else:
            current_app.logger.warning(
                "Rule pack add form invalid entries: %s",
                json.dumps(rule_pack_form.errors),
            )
            flash(str(rule_pack_form.errors), "error")
            return rule_packs_form_page(edit=False, rule_pack_form=rule_pack_form)
    # GET / Display form
    else:
        return rule_packs_form_page(edit=False, rule_pack_form=RulePackForm())


@blueprint.route("/rules/packs/edit/<rule_pack_id>", methods=["GET", "POST"])
@login_required
def rules_packs_edit(rule_pack_id):
    # Get the rule pack to edit
    edit_rule_pack = RulePack.query.filter_by(id=rule_pack_id).first_or_404()
    # POST / Form submitted
    if "save-rule-pack" in request.form:
        rule_pack_form = RulePackForm()
        # Dynamically adds choices for multiple selection fields
        rule_pack_form.languages.choices = (
            (l.id, l.name) for l in SupportedLanguage.query.all()
        )
        # Form is valid
        if rule_pack_form.validate_on_submit():
            # Perform additional custom validation
            err = validate_languages_rules(rule_pack_form)
            if err is not None:
                flash(err, "error")
                return rule_packs_form_page(edit=True, rule_pack_form=rule_pack_form)
            # Set applicable languages
            rp_languages = SupportedLanguage.query.filter(
                SupportedLanguage.id.in_(rule_pack_form.languages.data)
            ).all()
            # Get associated rules
            rule_ids = comma_separated_to_list(rule_pack_form.rules.data)
            rp_rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()
            # Update rule pack attributes
            edit_rule_pack.name = rule_pack_form.name.data
            edit_rule_pack.description = rule_pack_form.description.data
            edit_rule_pack.languages = rp_languages
            edit_rule_pack.rules = rp_rules
            db.session.commit()
            current_app.logger.info(
                "Rule pack updated (rule_pack.id=%i)", edit_rule_pack.id
            )
            flash("Rule pack has been successfully saved", "success")
            return rule_packs_form_page(edit=True, rule_pack_form=rule_pack_form)
        # Form is invalid, form.error is populated
        else:
            current_app.logger.warning(
                "Rule pack edit form invalid entries: %s",
                json.dumps(rule_pack_form.errors),
            )
            flash(rule_pack_form.errors, "error")
            return rule_packs_form_page(edit=True, rule_pack_form=rule_pack_form)
    # GET / Display the rule pack
    else:
        # Load form from the given rule pack
        rule_pack_form = RulePackForm(obj=edit_rule_pack)
        # Dynamically adds choices for multiple selection fields
        rule_pack_form.languages.choices = (
            (l.id, l.name) for l in SupportedLanguage.query.all()
        )
        # Manually handle languages and rules fields
        rule_pack_form.languages.data = list()
        for c_lang in edit_rule_pack.languages:
            rule_pack_form.languages.data.append(c_lang.id)
        rule_pack_form.rules.data = ""
        for c_rule in edit_rule_pack.rules:
            rule_pack_form.rules.data = rule_pack_form.rules.data + "," + str(c_rule.id)
        return rule_packs_form_page(edit=True, rule_pack_form=rule_pack_form)


@blueprint.route("/rules/packs/remove/<rule_pack_id>")
@login_required
def rules_packs_remove(rule_pack_id):
    rule_pack = RulePack.query.filter_by(id=rule_pack_id).first_or_404()
    db.session.delete(rule_pack)
    db.session.commit()
    current_app.logger.info("Rule pack deleted (rule_pack.id=%i)", rule_pack.id)
    flash("Rule pack has been successfully removed", "success")
    return redirect(url_for("rules_blueprint.rule_packs_list"))


@blueprint.route("/rules/add", methods=["GET", "POST"])
@login_required
def rules_add():
    rule_form = RulesAddForm()
    # POST / Form submitted
    if "save-local-rule" in request.form:
        if rule_form.validate_on_submit():
            rule_path = add_new_rule(rule_form.name.data, rule_form.rule.data)
            save_rule_in_db(rule_path)
            flash("New rule has been successfully added.", "success")
        else:
            current_app.logger.warning(
                "Invalid rule form entries: %s",
                json.dumps(rule_form.errors),
            )
            flash(rule_form.errors, "error")
    return render_template("add_rules.html", form=rule_form, user=current_user,)
