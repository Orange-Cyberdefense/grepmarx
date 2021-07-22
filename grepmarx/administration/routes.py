"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
from grepmarx.administration.util import validate_user_form
from grepmarx import db
from grepmarx.administration import blueprint
from grepmarx.administration.forms import UserForm
from grepmarx.base import util
from grepmarx.base.models import User
from flask import current_app, redirect, render_template, request, url_for
from flask_login import current_user, login_required


@blueprint.route("/users")
@login_required
def users_list():
    users = User.query.all()
    return render_template(
        "users_list.html", users=users, user=current_user, segment="users"
    )


def user_form_page(edit=False, user_form=None, error_message="", success_message=""):
    # No form given: create an empty one
    if user_form is None:
        user_form = UserForm()
    return render_template(
        "users_edit.html",
        edit=edit,
        form=user_form,
        user=current_user,
        error_message=error_message,
        success_message=success_message,
    )


@blueprint.route("/users/add", methods=["GET", "POST"])
@login_required
def user_add():
    user_form = UserForm()
    # POST / Form submitted
    if "save-user" in request.form:
        # Form is valid
        if user_form.validate_on_submit():
            # Perform additional custom checks
            err = validate_user_form(user_form)
            if err is not None:
                return user_form_page(error_message=err)
            # We can create the user
            user = User(**request.form)
            # Remove id attribute to let the DB set it
            delattr(user, "id")
            db.session.add(user)
            db.session.commit()
            current_app.logger.info("New user added (user.id=%i)", user.id)
            return user_form_page(
                edit=True,
                user_form=user_form,
                success_message="New user successfully added",
            )
        # Form is invalid, form.error is populated
        else:
            current_app.logger.warning("User add form invalid entries: %s", json.dumps(user_form.errors))
            return user_form_page(user_form=user_form)
    # GET / Display form
    else:
        return user_form_page(user_form=user_form)


@blueprint.route("/users/edit/<user_id>", methods=["GET", "POST"])
@login_required
def users_edit(user_id):
    edit_user = User.query.filter_by(id=user_id).first()
    # POST / Form submitted
    if "save-user" in request.form:
        user_form = UserForm()
        # Form is valid
        if user_form.validate_on_submit():
            # Perform additional custom validation
            err = validate_user_form(
                form=user_form,
                skip_username=(edit_user.username == user_form.username.data),
                skip_email=(edit_user.email == user_form.email.data),
                skip_password=(user_form.password.data == ""),
            )
            if err is not None:
                return user_form_page(edit=True, user_form=user_form, error_message=err)

            # Change the password if needed only
            if user_form.password.data == "":
                edit_password = edit_user.password
            else:
                edit_password = util.hash_pass(user_form.password.data)
            # User can be updated
            user_form.populate_obj(edit_user)
            edit_user.password = edit_password
            db.session.commit()
            current_app.logger.info("User updated (user.id=%i)", user_form.id.data)
            return user_form_page(
                edit=True,
                user_form=user_form,
                success_message="User successfully updated",
            )
        # Form is invalid, form.error is populated
        else:
            current_app.logger.warning("User edit form invalid entries: %s", json.dumps(user_form.errors))
            return user_form_page(
                edit=True,
                user_form=user_form,
            )
    # GET / Display form
    else:
        user_form = UserForm(obj=edit_user)
        return user_form_page(
            edit=True,
            user_form=user_form,
        )


@blueprint.route("/users/remove/<user_id>")
@login_required
def users_remove(user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    current_app.logger.info("User removed (user.id=%i)", user.id)
    return redirect(url_for("administration_blueprint.users_list"))
