# Generated by default/object.tt
package Paws::SSOIdentityStore::User;
  use Moose;
  has UserId => (is => 'ro', isa => 'Str', required => 1);
  has UserName => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SSOIdentityStore::User

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SSOIdentityStore::User object:

  $service_obj->Method(Att1 => { UserId => $value, ..., UserName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SSOIdentityStore::User object:

  $result = $service_obj->Method(...);
  $result->Att1->UserId

=head1 DESCRIPTION

A user object, which contains a specified userE<rsquo>s metadata and
attributes.

=head1 ATTRIBUTES


=head2 B<REQUIRED> UserId => Str

The identifier for a user in the identity store.


=head2 B<REQUIRED> UserName => Str

Contains the userE<rsquo>s username value. The length limit is 128
characters. This value can consist of letters, accented characters,
symbols, numbers and punctuation. The characters
E<ldquo>E<lt>E<gt>;:%E<rdquo> are excluded. This value is specified at
the time the user is created and stored as an attribute of the user
object in the identity store.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SSOIdentityStore>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

